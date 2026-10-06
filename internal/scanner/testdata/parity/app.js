// syck parity fixture: AWS access key id in JS source.
const config = {
  region: "us-east-1",
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
};

function load() {
  return config.region;
}

module.exports = { load };
