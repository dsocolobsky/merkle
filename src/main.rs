use std::hash::{DefaultHasher, Hash, Hasher};

fn calculate_next_level(vec: &Vec<String>) -> Vec<String> {
    let mut hasher = DefaultHasher::new();
    let mut next_level: Vec<String> = vec![];
    for i in (0..vec.len()-1).step_by(2) {
        let s1 = vec[i].clone();
        let s2 = vec[i+1].clone();
        let s = String::from(format!("{s1}{s2}"));
        s.hash(&mut hasher);
        next_level.push(hasher.finish().to_string());
    }
    next_level
}

fn create_initial_level(vec: &Vec<i32>) -> Vec<String> {
    let mut hasher = DefaultHasher::new();
    vec.iter().map(|e| {
        e.hash(&mut hasher);
        hasher.finish().to_string()
    }).collect()
}

fn main() {
    let initial = create_initial_level(&vec![3, 4, 5, 6]);
    let mut actual: Box<Vec<String>> = Box::new(initial);
    dbg!(&actual);
    while (actual.len() > 1) {
        actual = Box::new(calculate_next_level(&actual));
        dbg!(&actual);
    }
}
