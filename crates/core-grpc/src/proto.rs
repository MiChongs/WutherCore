use prost::Message;

/// Exact protobuf shape of Xray's `encoding.Hunk`.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Hunk {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// Exact protobuf shape of Xray's `encoding.MultiHunk`.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct MultiHunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub data: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_matches_pinned_xray_protobuf_wire() {
        let message = Hunk {
            data: vec![0, 1, 127, 128],
        };
        assert_eq!(message.encode_to_vec(), [0x0a, 0x04, 0, 1, 127, 128]);
    }

    #[test]
    fn multi_hunk_repeats_field_one_without_packing() {
        let message = MultiHunk {
            data: vec![b"ab".to_vec(), Vec::new(), b"c".to_vec()],
        };
        assert_eq!(
            message.encode_to_vec(),
            [0x0a, 0x02, b'a', b'b', 0x0a, 0x00, 0x0a, 0x01, b'c']
        );
    }
}
