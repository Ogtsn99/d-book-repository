pub fn check_proof(mut s1: String, proofs: &Vec<String>, root: &String) -> bool {
    for proof in proofs {
        s1 = calc_hash_from_two(&s1, proof);
    }
    s1 == *root
}

fn calc_hash_from_two(s1: &String, s2: &String) -> String {
    if s1 < s2 {
        sha256::digest(s1.clone() + &*s2.clone())
    } else {
        sha256::digest(s2.clone() + &*s1.clone())
    }
}