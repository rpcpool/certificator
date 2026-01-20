{ pkgs, lib, config, inputs, ... }:

let
  # Read Go version from go.mod automatically
  goModContent = builtins.readFile ./go.mod;
  goVersionLine = lib.findFirst
    (line: lib.hasPrefix "go " line)
    "go 1.24"
    (lib.splitString "\n" goModContent);
  goVersion = lib.removePrefix "go " (lib.trim goVersionLine);

  # HAProxy Data Plane API - built from source
  dataplaneapi = pkgs.buildGoModule rec {
    pname = "dataplaneapi";
    version = "3.0.2";

    src = pkgs.fetchFromGitHub {
      owner = "haproxytech";
      repo = "dataplaneapi";
      rev = "v${version}";
      hash = "sha256-SFI7WKPxF31b97Q4EWbsTbp3laXHcUfdg4hlFUiml5A=";
    };

    vendorHash = "sha256-vm+NUf8OCW+jCiPY13d/MjQpy3/NxEwx7Zol2bP+eF4=";

    # Skip tests as they require network access
    doCheck = false;

    ldflags = [
      "-s" "-w"
      "-X main.GitRepo=https://github.com/haproxytech/dataplaneapi"
      "-X main.GitTag=v${version}"
    ];

    meta = with lib; {
      description = "HAProxy Data Plane API";
      homepage = "https://github.com/haproxytech/dataplaneapi";
      license = licenses.asl20;
    };
  };

in
{
  env = {
    CGO_ENABLED = "0";
    # Use the Go version from go.mod via GOTOOLCHAIN
    # This allows the Go toolchain to download the exact version if needed
    GOTOOLCHAIN = lib.mkForce "go${goVersion}+auto";
  };

  packages = with pkgs; [
    git
    go-tools        # staticcheck, etc.
    gotools         # goimports, godoc, etc.
    golangci-lint   # Comprehensive linter
    delve           # Debugger
    gopls           # Language server
    gomodifytags    # Modify struct tags
    impl            # Generate interface stubs
    gotests         # Generate tests
    gocover-cobertura # Coverage reports
    goreleaser      # Release automation
    gotestsum       # Better test output
    jq              # JSON processing
    yq              # YAML processing
    curl            # HTTP client
    socat           # Socket testing (useful for HAProxy runtime API testing)
    haproxy         # HAProxy load balancer
    dataplaneapi    # HAProxy Data Plane API
    openssl         # For generating test certificates
  ];

  languages.go = {
    enable = true;
  };

  scripts = {
    build.exec = ''
      echo "Building certificator..."
      go build -v ./cmd/certificator
      go build -v ./cmd/certificatee
      echo "Build complete!"
    '';

    test.exec = ''
      echo "Running tests..."
      go test -v ./...
    '';

    test-coverage.exec = ''
      echo "Running tests with coverage..."
      go test -v -coverprofile=coverage.out ./...
      go tool cover -html=coverage.out -o coverage.html
      echo "Coverage report: coverage.html"
    '';

    tidy.exec = ''
      echo "Tidying dependencies..."
      go mod tidy
      go mod verify
    '';

    # Run all checks (format, lint, vet, test)
    check.exec = ''
      echo "=== Running all checks ==="
      echo ""
      echo ">>> Formatting..."
      gofmt -w -s .
      goimports -w .
      echo ""
      echo ">>> Running go vet..."
      go vet ./...
      echo ""
      echo ">>> Running golangci-lint..."
      golangci-lint run ./...
      echo ""
      echo ">>> Running tests..."
      go test -v ./...
      echo ""
      echo "=== All checks passed! ==="
    '';

    # Generate test stubs for a file
    generate-tests.exec = ''
      if [ -z "$1" ]; then
        echo "Usage: generate-tests <file.go>"
        exit 1
      fi
      gotests -all -w "$1"
    '';

    # Watch tests (requires watchexec)
    test-watch.exec = ''
      echo "Watching for changes and running tests..."
      ${lib.getExe pkgs.watchexec} -e go -- go test -v ./...
    '';

    # Clean build artifacts
    clean.exec = ''
      echo "Cleaning build artifacts..."
      rm -f certificator certificatee
      rm -f coverage.out coverage.html
      go clean -cache -testcache
      echo "Clean complete!"
    '';

    # Integration test for certificatee list-certs
    integration-test.exec = ''
      echo "=== Running Integration Tests ==="
      ${lib.getExe pkgs.bash} ./test/integration/run-tests.sh
    '';
  };

  # Shell hook - runs when entering the devenv
  enterShell = ''
    echo ""
    echo "=========================================="
    echo "  Certificator Development Environment"
    echo "=========================================="
    echo ""
    echo "Go version (from go.mod): ${goVersion}"
    echo "Go version (active):      $(go version | cut -d' ' -f3)"
    echo "HAProxy version:          $(haproxy -v | head -1)"
    echo "Data Plane API:           $(dataplaneapi --version 2>&1 | head -1 || echo 'available')"
    echo ""
    echo "Available commands:"
    echo "  build            - Build certificator and certificatee"
    echo "  test             - Run all tests"
    echo "  test-coverage    - Run tests with coverage report"
    echo "  test-watch       - Watch for changes and run tests"
    echo "  tidy             - Tidy go.mod dependencies"
    echo "  check            - Run all checks (fmt, vet, lint, test)"
    echo "  clean            - Clean build artifacts"
    echo "  integration-test - Run HAProxy integration tests"
    echo ""
  '';

  # Test configuration for `devenv test`
  enterTest = ''
    echo "Running devenv tests..."
    go version
    go test -v ./...

    echo ""
    echo "Running integration tests..."
    bash ./test/integration/run-tests.sh
  '';

  git-hooks.hooks = {
    gofmt.enable = true;
    govet.enable = true;
    staticcheck.enable = true;
  };
}
