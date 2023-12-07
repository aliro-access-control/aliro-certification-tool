# aliro-certification-tool
A test harness and tooling designed to simplify development, testing, and certification for devices, guided by the Connectivity Standards Alliance - ACWG. 

## Getting Started
Follow the documentation here from the CSA Test Harness Repo. 

But use this repo in step 6.:

```sh
git clone git@github.com:csa-access-control/aliro-certification-tool.git
```

CSA Test Harness setup guide:
https://github.com/project-chip/certification-tool/blob/main/docs/Raspberry%20Pi-Setup.md


## Authoring Test Scripts

Aliro test scripts are located in `test_collections/aliro`. They must be located as the same file structure as the current `sample_collection` with `SampleSuite` and `SampleTestCase`. This ensures, that the Test Harness can automatically discover the tests on launch.

After changing/adding test scripts, the test harness backend must be restarted. This can be done using this command:

```sh
docker restart aliro-certification-tool_backend_1
```

Test Harness backend logs can be streamed using this command:
```sh
docker restart aliro-certification-tool_backend_1
```