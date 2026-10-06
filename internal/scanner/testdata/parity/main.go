package main

// syck parity fixture: a JWT literal embedded in Go source.
const serviceToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.9f3c7a1e5b8d42f6c0a9e3b7d15f842c"

func main() {
	println(serviceToken)
}
