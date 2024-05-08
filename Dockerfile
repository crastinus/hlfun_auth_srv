FROM rust:1.77-buster AS build

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release  

# FROM rust:1.77-buster as deploy
FROM debian:10 as deploy

COPY --from=build /usr/src/app/target/release/hlfun_srv /usr/bin

EXPOSE 8080

CMD ["/usr/bin/hlfun_srv"]
