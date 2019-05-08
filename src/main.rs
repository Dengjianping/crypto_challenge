use std::path::Path;
use std::collections::HashMap;
use std::fs::File;
use std::io::{ self, Read };


fn main() {
    // challenge 1
    let challenge_1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("challenge 1: {}", hex2base64(challenge_1));
    
    // challenge 2
    let challenge_2_message = "1c0111001f010100061a024b53535009181c";
    let challenge_2_key = "686974207468652062756c6c277320657965";
    println!("challenge 2: {}", fix_xor(challenge_2_message, challenge_2_key));
    
    // challenge 3
    let challenge_3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    println!("challenge 3: {:?}", single_byte_xor_cipher(challenge_3));
    
    // challenge 4
    let challenge_4 = concat!(env!("CARGO_MANIFEST_DIR"), "/4.txt");
    println!("challenge 4: {:?}", detect_single_character_xor(challenge_4));
    
    // challenge 5
    let challenge_5_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let challenge_5_key = "ICE";
    println!("challenge 5: {}", repeating_key_xor(challenge_5_text, challenge_5_key, true));
    
    // challenge 6
    let challenge_6 = concat!(env!("CARGO_MANIFEST_DIR"), "/6.txt");
    println!("challenge 6: {:?}", break_repeating_key_xor(challenge_6));
}

#[allow(non_upper_case_globals)]
const alphabet_base64: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn get_txt_content<T: AsRef<Path>>(path: T) -> String {
    let file = File::open(path.as_ref()).unwrap();
    
    let mut buff = io::BufReader::new(file);
    let mut content = String::new();
    let _ = buff.read_to_string(&mut content);
    content
}

fn decrypt_base64<T: AsRef<str>>(base64_str: T) -> String {
    // remove all symbol '='
    let trimed_str = base64_str.as_ref().trim_end_matches('=');
    
    let bin_str: String = trimed_str.chars().map(|c| {
        let position = alphabet_base64.chars().position(|v| v == c).unwrap();
        format!("{:06b}", position)
    }).collect();

    let step = 8usize;
    let padded_zeros_count = bin_str.len() % step;
    // split the string by padded zeros
    let (splited, _) = bin_str.as_str().split_at(bin_str.len() - padded_zeros_count);
    
    let result: String = splited.chars().step_by(step).enumerate().map(|(index, _)| {
        let slice = &splited[step * index..step * index + step];
        let hex2u8 = u8::from_str_radix(slice, 2).unwrap();
        char::from(hex2u8)
    }).collect();
    result
}

// challenge 1
fn hex2base64<T: AsRef<str>>(hex_str: T) -> String {
    // determine how many '=' will be added
    let equal_count = hex_str.as_ref().len() % 3;
    
    // generate the string represented as binary
    let mut step = 2usize;
    let mut bin_str: String = hex_str.as_ref().chars().step_by(step).enumerate().map(|(index, _)| {
        let slice = &hex_str.as_ref()[step * index..step * index + step];
        let hex2u8 = u8::from_str_radix(slice, 16).unwrap();
        format!("{:08b}", hex2u8)
    }).collect();
    
    step = 6usize;
    // padding the extra '0' to ensure the length of string is multiple of 6
    if bin_str.len() % step != 0 {
        let padding_str: String = std::iter::repeat('0').take(step - bin_str.len() % step).collect();
        bin_str += &padding_str;
    }

    let result: String = bin_str.chars().step_by(step).enumerate().map(|(index, _)| {
        let slice = &bin_str[step * index..step * index + step];
        let hex2u8 = u8::from_str_radix(slice, 2).unwrap();
        // look up the table
        alphabet_base64.chars().nth(hex2u8 as usize).unwrap()
    }).collect();
    match equal_count {
        1 => result + "=",
        2 => result + "==",
        _ => result
    }
}

// challenge 2
fn fix_xor<T: AsRef<str>>(message: T, key: T) -> String {
    // remove unwrap, judge length of input string, error handling
    let (msg_tr, key_str) = (message.as_ref(), key.as_ref());
    
    let step = 2usize;
    let result: String = msg_tr.chars().step_by(step).enumerate().map(|(index, _)| {
        let message_slice = &msg_tr[step * index..step * index + step];
        let key_slice = &key_str[step * index..step * index + step];
        let msg_u8 = u8::from_str_radix(message_slice, 16).unwrap();
        let key_u8 = u8::from_str_radix(key_slice, 16).unwrap();
        format!("{:02x}", msg_u8 ^ key_u8)
    }).collect();
    result
}

// challenge 3
fn single_byte_xor_cipher<T: AsRef<str>>(hex: T) -> (String, usize, f32) {
    // these data from here: http://www.data-compression.com/english.html#first
    // clippy likes this format 0.012_424_8
    #[allow(clippy::unreadable_literal)]
    let word_fq_table: HashMap<char, f32> = [
        ('a', 0.0651738), ('b', 0.0124248), ('c', 0.0217339), ('d', 0.0349835), ('e', 0.1041442),
        ('f', 0.0197881), ('g', 0.0158610), ('h', 0.0492888), ('i', 0.0558094), ('j', 0.0009033),
        ('k', 0.0050529), ('l', 0.0331490), ('m', 0.0202124), ('n', 0.0564513), ('o', 0.0596302),
        ('p', 0.0137645), ('q', 0.0008606), ('r', 0.0497563), ('s', 0.0515760), ('t', 0.0729357),
        ('u', 0.0225134), ('v', 0.0082903), ('w', 0.0171272), ('x', 0.0013692), ('y', 0.0145984),
        ('z', 0.0007836), (' ', 0.1918182)
    ].iter().cloned().collect();
    
    let hex_ref = hex.as_ref();
    let step = 2usize;
    
    let all_decoded: Vec<_> = (0..=255u8).map(|c| {
        let decoded: String = hex_ref.chars().step_by(step).enumerate().map(|(index, _)| {
            let hex_slice = &hex_ref[step* index..step*index + step];
            let hex2u8 = u8::from_str_radix(hex_slice, 16).unwrap();
            char::from(hex2u8 ^ c)
        }).collect();
        decoded
    }).collect();
    
    let all_score: Vec<f32> = all_decoded.iter().map(|decoded| {
        decoded.as_str().chars().map(|c| {
            let lower_char = c.to_lowercase().next().unwrap();
            word_fq_table.get(&lower_char).map_or(0.0f32, |v| *v)
        }).sum()
    }).collect();
    
    // max_element represents as (index, score)
    let max_element = all_score.iter().enumerate().max_by(|x, y| x.1.partial_cmp(&y.1).unwrap());

    let (max_index, score) = max_element.unwrap();
    let result: String = hex_ref.chars().step_by(step).enumerate().map(|(index, _)| {
        let hex_slice = &hex_ref[step* index..step*index + step];
        let xor_u8 = max_index as u8 ^ u8::from_str_radix(hex_slice, 16).unwrap();
        char::from(xor_u8)
    }).collect();
    (result, max_index, *score)
}

// challenge 4
fn detect_single_character_xor<T: AsRef<Path>>(path: T) -> (String, usize, f32) {
    let txt_content = get_txt_content(path.as_ref());
    
    let r: Vec<_> = txt_content.lines().map(single_byte_xor_cipher).collect();
    
    // (index, (String, index_1, score), find out the which line has the max score
    let (max_index, _) = r.iter().enumerate().max_by(|x, y| (x.1).2.partial_cmp(&(y.1).2).unwrap()).unwrap();
    
    single_byte_xor_cipher(txt_content.lines().nth(max_index).as_ref().unwrap())
}

// challenge 5
fn repeating_key_xor<T: AsRef<str>>(text: T, key: T, hexed: bool) -> String {
    // create a cycled iterator
    let mut key_cycle_iter = key.as_ref().chars().cycle();
    
    let result: String = text.as_ref().chars().map(|c| {
        let xor_u8 = c as u8 ^ *key_cycle_iter.next().as_ref().unwrap() as u8;
        if hexed {
            format!("{:02x}", xor_u8)
        } else {
            format!("{}", char::from(xor_u8))
        }
    }).collect();
    result
}

// challenge 6
fn break_repeating_key_xor<T: AsRef<Path>>(path: T) -> (String, String) {
    let txt_content = get_txt_content(path.as_ref());
    let decrypted_str: String = txt_content.lines().map(decrypt_base64).collect();
    
    // get the length of key
    let mut normalized_hamming_distances: Vec<_> = (2..40).map(|key_size| {
        // divide the string by key_size
        let key_size_blocks: Vec<_> = decrypted_str.as_str().chars().step_by(key_size).enumerate().map(|(index, _)| {
            &decrypted_str.as_str()[index * key_size..index * key_size + key_size]
        }).take(4).collect(); // take 4 key_size blocks
        
        // generate all groups
        let mut iter = key_size_blocks.iter();
        let mut groups: Vec<(&str, &str)> = Vec::new();
        while let Some(i) = iter.next() {
            let mut next = iter.clone();
            while let Some(j) = next.next() {
                groups.push((i, j));
            }
        }
        
        // caculate hamming distance
        let hamming_distance: u32 = groups.iter().map(|tuple| {
            let ones: u32 = tuple.0.chars().zip(tuple.1.chars()).map(|(t0, t1)| {
                let xor_u8 = t0 as u8 ^ t1 as u8;
                xor_u8.count_ones()
            }).sum();
            ones
        }).sum();
        // (avg_hamming_distance, key_size)
        (hamming_distance as f32 / key_size as f32, key_size)
    }).collect();
    
    // sotr the scores
    normalized_hamming_distances.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
    
    // all_decrypted represents as Vec<(key, index, score)>
    let all_decrypted: Vec<_> = normalized_hamming_distances.iter().take(3).map(|s| {
        // find all keys
        let key: String = (0..s.1).map(|i| {
            let tranposed_str: String = decrypted_str.as_str().chars().enumerate().filter_map(|(index, val)| {
                // make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
                if index % s.1 == i {
                    Some(format!("{:02x}", val as u8)) 
                } else { None }
            }).collect();
            // 
            let char_for_key = single_byte_xor_cipher(tranposed_str).1 as u8;
            char::from(char_for_key)
        }).collect();
        let hexed_key: String = key.chars().map(|c| format!("{:02x}", c as u8)).collect();
        
        // decrypt the string by key
        single_byte_xor_cipher(&hexed_key)
    }).collect();
    
    // find the max score by key
    let max_score = all_decrypted.iter().max_by(|x, y| x.2.partial_cmp(&y.2).unwrap()).unwrap();
    let result = repeating_key_xor(&decrypted_str, &max_score.0, false);
    // (key, result)
    (max_score.0.clone(), result)
}