FROM golang:1.22-alpine
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o npvtbot .
EXPOSE 8080
CMD ["./npvtbot"]
