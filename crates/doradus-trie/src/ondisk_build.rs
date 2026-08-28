//! Bounded external sorting and root-index construction for the disk trie.

use super::*;

pub(super) fn flush_run(
    dir: &Path,
    prefix: &str,
    key_size: usize,
    records: &mut Vec<Vec<u8>>,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    records.sort_unstable_by(|left, right| {
        record_key(left, key_size).cmp(record_key(right, key_size))
    });
    records.dedup_by(|left, right| record_key(left, key_size) == record_key(right, key_size));
    let path = dir.join(format!(
        ".{prefix}.run-{}",
        NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_run(&path, records.iter());
    if result.is_ok() {
        paths.push(path);
        records.clear();
    } else {
        let _ = fs::remove_file(&path);
    }
    result
}

fn write_run<'a>(path: &Path, records: impl Iterator<Item = &'a Vec<u8>>) -> Result<()> {
    let result = (|| {
        let mut file = File::create(path).map_err(io_error)?;
        for record in records {
            file.write_all(record).map_err(io_error)?;
        }
        file.sync_all().map_err(io_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn record_key(record: &[u8], key_size: usize) -> &[u8] {
    if key_size == DOMAIN_KEY_SIZE {
        let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
        &record[2..2 + length]
    } else {
        &record[..key_size]
    }
}

pub(super) fn merge_runs_to_table(
    path: &Path,
    kind: u32,
    record_size: usize,
    key_size: usize,
    mut runs: Vec<PathBuf>,
) -> Result<()> {
    while runs.len() > MERGE_FAN_IN {
        let mut merged = Vec::with_capacity(runs.len().div_ceil(MERGE_FAN_IN));
        for group in runs.chunks(MERGE_FAN_IN) {
            let output = path.with_extension(format!(
                "merge-{}",
                NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
            ));
            merge_run_group(group, &output, record_size, key_size)?;
            merged.push(output);
        }
        for input in runs {
            let _ = fs::remove_file(input);
        }
        runs = merged;
    }

    let temp = path.with_extension(format!(
        "tmp-{}",
        NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = File::create(&temp).map_err(io_error)?;
        let mut header = [0u8; HEADER_SIZE];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&kind.to_le_bytes());
        header[16..20].copy_from_slice(&(record_size as u32).to_le_bytes());
        file.write_all(&header).map_err(io_error)?;
        let count = merge_run_group_to_writer(&runs, &mut file, record_size, key_size)?;
        file.seek(SeekFrom::Start(24)).map_err(io_error)?;
        file.write_all(&count.to_le_bytes()).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        fs::rename(&temp, path).map_err(io_error)
    })();
    for input in runs {
        let _ = fs::remove_file(input);
    }
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn merge_run_group(
    inputs: &[PathBuf],
    output: &Path,
    record_size: usize,
    key_size: usize,
) -> Result<()> {
    let result = (|| {
        let mut file = File::create(output).map_err(io_error)?;
        merge_run_group_to_writer(inputs, &mut file, record_size, key_size)?;
        file.sync_all().map_err(io_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

fn merge_run_group_to_writer(
    inputs: &[PathBuf],
    output: &mut File,
    record_size: usize,
    key_size: usize,
) -> Result<u64> {
    let mut cursors = inputs
        .iter()
        .map(|path| RunCursor::open(path, record_size))
        .collect::<Result<Vec<_>>>()?;
    let mut previous = None::<Vec<u8>>;
    let mut count = 0;
    while let Some(best) = cursors
        .iter()
        .enumerate()
        .filter_map(|(index, cursor)| cursor.current.as_ref().map(|record| (index, record)))
        .min_by(|(_, left), (_, right)| record_key(left, key_size).cmp(record_key(right, key_size)))
        .map(|(index, _)| index)
    {
        let record = cursors[best].current.take().expect("selected run record");
        let duplicate = previous
            .as_ref()
            .is_some_and(|last| record_key(last, key_size) == record_key(&record, key_size));
        if !duplicate {
            output.write_all(&record).map_err(io_error)?;
            count += 1;
            previous = Some(record.clone());
        }
        cursors[best].advance()?;
    }
    Ok(count)
}

pub(super) fn write_root_index(domain_path: &Path, root_path: &Path) -> Result<()> {
    let domain = File::open(domain_path).map_err(io_error)?;
    let mut domain_header = [0u8; HEADER_SIZE];
    read_exact_at(&domain, &mut domain_header, 0).map_err(io_error)?;
    let count = u64::from_le_bytes(domain_header[24..32].try_into().unwrap());
    let temp = root_path.with_extension(format!(
        "tmp-{}",
        NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut output = File::create(&temp).map_err(io_error)?;
        let mut header = [0u8; HEADER_SIZE];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&3u32.to_le_bytes());
        header[16..20].copy_from_slice(&(ROOT_RECORD_SIZE as u32).to_le_bytes());
        output.write_all(&header).map_err(io_error)?;

        let mut previous = Vec::new();
        let mut roots = 0u64;
        let mut record = vec![0u8; DOMAIN_RECORD_SIZE];
        for index in 0..count {
            read_exact_at(
                &domain,
                &mut record,
                HEADER_SIZE as u64 + index * DOMAIN_RECORD_SIZE as u64,
            )
            .map_err(io_error)?;
            let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
            let key = &record[2..2 + length.min(DOMAIN_KEY_SIZE)];
            let root = key.split(|byte| *byte == b'.').next().unwrap_or_default();
            if previous.as_slice() == root {
                continue;
            }
            if root.len() > ROOT_KEY_SIZE {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "domain root label is too large",
                ));
            }
            let mut root_record = vec![0u8; ROOT_RECORD_SIZE];
            root_record[..2].copy_from_slice(&(root.len() as u16).to_le_bytes());
            root_record[2..2 + root.len()].copy_from_slice(root);
            output.write_all(&root_record).map_err(io_error)?;
            previous.clear();
            previous.extend_from_slice(root);
            roots += 1;
        }
        output.seek(SeekFrom::Start(24)).map_err(io_error)?;
        output.write_all(&roots.to_le_bytes()).map_err(io_error)?;
        output.sync_all().map_err(io_error)?;
        fs::rename(&temp, root_path).map_err(io_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(super) fn load_root_labels(path: PathBuf) -> Result<Vec<Vec<u8>>> {
    let file = File::open(&path).map_err(io_error)?;
    let mut header = [0u8; HEADER_SIZE];
    read_exact_at(&file, &mut header, 0).map_err(io_error)?;
    let count = u64::from_le_bytes(header[24..32].try_into().unwrap());
    if &header[..8] != MAGIC
        || u32::from_le_bytes(header[8..12].try_into().unwrap()) != VERSION
        || u32::from_le_bytes(header[12..16].try_into().unwrap()) != 3
        || u32::from_le_bytes(header[16..20].try_into().unwrap()) != ROOT_RECORD_SIZE as u32
    {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("invalid doradus trie root index: {}", path.display()),
        ));
    }
    let expected = HEADER_SIZE as u64 + count.saturating_mul(ROOT_RECORD_SIZE as u64);
    if file.metadata().map_err(io_error)?.len() != expected {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("truncated doradus trie root index: {}", path.display()),
        ));
    }
    let mut roots = Vec::with_capacity(count as usize);
    let mut record = [0u8; ROOT_RECORD_SIZE];
    for index in 0..count {
        read_exact_at(
            &file,
            &mut record,
            HEADER_SIZE as u64 + index * ROOT_RECORD_SIZE as u64,
        )
        .map_err(io_error)?;
        let length = u16::from_le_bytes(record[..2].try_into().unwrap()) as usize;
        if length > ROOT_KEY_SIZE {
            return Err(Error::new(ErrorKind::Protocol, "invalid root label length"));
        }
        roots.push(record[2..2 + length].to_vec());
    }
    Ok(roots)
}

struct RunCursor {
    file: File,
    record_size: usize,
    offset: u64,
    length: u64,
    current: Option<Vec<u8>>,
}

impl RunCursor {
    fn open(path: &Path, record_size: usize) -> Result<Self> {
        let file = File::open(path).map_err(io_error)?;
        let length = file.metadata().map_err(io_error)?.len();
        if length % record_size as u64 != 0 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid disk trie run size",
            ));
        }
        let mut cursor = Self {
            file,
            record_size,
            offset: 0,
            length,
            current: None,
        };
        cursor.advance()?;
        Ok(cursor)
    }

    fn advance(&mut self) -> Result<()> {
        if self.offset >= self.length {
            self.current = None;
            return Ok(());
        }
        let mut record = vec![0u8; self.record_size];
        read_exact_at(&self.file, &mut record, self.offset).map_err(io_error)?;
        self.offset += self.record_size as u64;
        self.current = Some(record);
        Ok(())
    }
}
