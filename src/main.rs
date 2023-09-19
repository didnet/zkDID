use hades::bench;
// The main function.

#[tokio::main]
async fn main() {
    bench::bench_all().await.unwrap();
}