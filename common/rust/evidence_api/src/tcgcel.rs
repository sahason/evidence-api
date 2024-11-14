use std::collections::HashMap;
use log::error;

struct TcgTpmsCelEvent {
    rec_num: i32,
    digests: Vec<TcgDigest>,
    content_type: Option<i32>,
    imr: Option<i32>,
    nv_index: Option<i32>,
    content: Option<Content>,
    encoding: Option<String>,
}

impl TcgTpmsCelEvent {
    fn new(
        rec_num: i32,
        digests: Vec<TcgDigest>,
        content_type: Option<i32>,
        imr: Option<i32>,
        nv_index: Option<i32>,
        content: Option<Content>,
    ) -> Self {
        if imr.is_some() && nv_index.is_some() {
            error!("Instantiate TPMS_CEL_EVENT with both IMR index and NV index. Failed to instantiate...");
            return Self {
                rec_num,
                digests,
                content_type,
                imr: None,
                nv_index: None,
                content: None,
                encoding: None,
            };
        }

        let content_type = content_type.unwrap_or_default();
        if !TcgTpmiCelContentType::is_valid_content(content_type) {
            error!("Invalid content specified. Failed to instantiate...");
            return Self {
                rec_num,
                digests,
                content_type: None,
                imr: None,
                nv_index: None,
                content: None,
                encoding: None,
            };
        }

        Self {
            rec_num,
            digests,
            content_type: Some(content_type),
            imr,
            nv_index,
            content,
            encoding: None,
        }
    }

    fn rec_num(&self) -> i32 {
        self.rec_num
    }

    fn set_rec_num(&mut self, rec_num: i32) {
        self.rec_num = rec_num;
    }

    fn index(&self) -> Option<i32> {
        self.imr.or(self.nv_index)
    }

    fn set_imr(&mut self, imr: i32) {
        self.imr = Some(imr);
    }

    fn set_nv_index(&mut self, nv_index: i32) {
        self.nv_index = Some(nv_index);
    }

    fn digests(&self) -> &Vec<TcgDigest> {
        &self.digests
    }

    fn set_digests(&mut self, digests: Vec<TcgDigest>) {
        self.digests = digests;
    }

    fn content(&self) -> Option<&Content> {
        self.content.as_ref()
    }

    fn set_content(&mut self, content: Content) {
        self.content = Some(content);
    }

    fn content_type(&self) -> Option<i32> {
        self.content_type
    }

    fn encoding(&self) -> Option<&String> {
        self.encoding.as_ref()
    }

    fn to_pcclient_format(&self) -> Option<TcgImrEvent> {
        match self.content_type {
            Some(TcgCelTypes::CEL_IMA_TEMPLATE) => {
                let event = self.content.as_ref()?.template_data();
                Some(TcgImrEvent::new(
                    self.imr?,
                    TcgEventType::IMA_MEASUREMENT_EVENT,
                    self.digests.clone(),
                    event.len(),
                    event,
                ))
            }
            Some(TcgCelTypes::CEL_PCCLIENT_STD) => Some(TcgImrEvent::new(
                self.imr?,
                self.content.as_ref()?.event_type(),
                self.digests.clone(),
                self.content.as_ref()?.event_data().len(),
                self.content.as_ref()?.event_data(),
            )),
            _ => {
                error!("Unsupported content to parse into TCG PCClient format.");
                None
            }
        }
    }

    fn encode(obj: &mut Self, encoding: i32) -> Option<Self> {
        match encoding {
            2 => {
                obj.encoding = Some("TLV".to_string());
                Some(Self::encoded_in_tlv(obj))
            }
            3 => {
                obj.encoding = Some("JSON".to_string());
                Some(Self::encoded_in_json(obj))
            }
            4 => {
                obj.encoding = Some("CBOR".to_string());
                Some(Self::encoded_in_cbor(obj))
            }
            _ => {
                error!("Invalid encoding specified. Returning the default encoding TLV");
                obj.encoding = Some("TLV".to_string());
                Some(Self::encoded_in_tlv(obj))
            }
        }
    }

    fn dump(&self) {
        let encoding = self.encoding();
        match encoding.as_deref() {
            Some("TLV") => {
                let rec_num = self.rec_num();
                let imr_index = self.index().unwrap_or_default();
                println!("-----------------------------Canonical Event Log Entry----------------------------");
                println!("Encoding          : {}", encoding.unwrap());
                println!("Rec Num           : {}", rec_num);
                println!("IMR               : {}", imr_index);
                println!(
                    "Type              : 0x{:X} ({})",
                    self.content_type.unwrap_or_default(),
                    TcgTpmiCelContentType::get_content_type_string(self.content_type.unwrap_or_default())
                );
                println!("Digests:");
                for (count, digest) in self.digests.iter().enumerate() {
                    println!(
                        "Algorithm_id[{}]   : {} ({})",
                        count,
                        digest.algo_id,
                        TcgAlgorithmRegistry::get_algorithm_string(digest.algo_id)
                    );
                    println!("Digest[{}]:", count);
                    let digest_blob = BinaryBlob::new(digest.hash.clone());
                    digest_blob.dump();
                }
                println!("Contents:");
                for (count, cnt) in self.content.as_ref().unwrap().value.iter().enumerate() {
                    println!(
                        "{}: {} = {}",
                        count,
                        cnt.attr_table[cnt.type],
                        cnt.value
                    );
                }
            }
            _ => {
                error!("Unsupported data format for dumping.");
            }
        }
    }

    fn encoded_in_tlv(obj: &mut Self) -> Self {
        // Implementation for TLV encoding
        obj.clone()
    }

    fn encoded_in_cbor(obj: &mut Self) -> Self {
        // Implementation for CBOR encoding
        obj.clone()
    }

    fn encoded_in_json(obj: &mut Self) -> Self {
        // Implementation for JSON encoding
        obj.clone()
    }
}

struct TcgDigest {
    // Fields for TcgDigest
}

struct Content {
    // Fields for Content
}

struct TcgImrEvent {
    // Fields for TcgImrEvent
}

impl TcgImrEvent {
    fn new(
        imr: i32,
        event_type: TcgEventType,
        digests: Vec<TcgDigest>,
        len: usize,
        event: &str,
    ) -> Self {
        // Implementation for TcgImrEvent
        Self {}
    }
}

struct TcgEventType;

struct TcgCelTypes;

impl TcgCelTypes {
    const CEL_IMA_TEMPLATE: i32 = 7;
    const CEL_PCCLIENT_STD: i32 = 5;
}

struct TcgTpmiCelContentType;

impl TcgTpmiCelContentType {
    fn is_valid_content(content_type: i32) -> bool {
        // Implementation for is_valid_content
        true
    }

    fn get_content_type_string(content_type: i32) -> &'static str {
        // Implementation for get_content_type_string
        "Content Type"
    }
}

struct TcgAlgorithmRegistry;

impl TcgAlgorithmRegistry {
    fn get_algorithm_string(alg_id: i32) -> &'static str {
        // Implementation for get_algorithm_string
        "Algorithm"
    }
}

struct BinaryBlob {
    value: Vec<u8>,
}

impl BinaryBlob {
    fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    fn dump(&self) {
        // Implementation for dump
    }
}
