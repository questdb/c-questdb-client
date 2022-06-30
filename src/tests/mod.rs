mod f64_serializer;
mod sender;
mod json_tests;
mod mock;

pub type TestError = Box<dyn std::error::Error>;
pub type TestResult = std::result::Result<(), TestError>;