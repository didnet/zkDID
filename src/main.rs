use hades::bench;
// for bench
#[tokio::main]
async fn main() {
    bench::bench_all().await.unwrap();
}