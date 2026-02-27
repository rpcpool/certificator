{
  description = "Certificator Development Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, devshell, git-hooks }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ devshell.overlays.default ];
        };

        lib = pkgs.lib;

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
          version = "2.9.21";

          src = pkgs.fetchFromGitHub {
            owner = "haproxytech";
            repo = "dataplaneapi";
            rev = "v${version}";
            hash = "sha256-HDSHdrObZopQtG7qHEv/NjKLkalF7hTRyuN7Vf6lHvY=";
          };

          vendorHash = "sha256-Mh9/C5V6Q/VJbPY4wqiXzzoZ0cs7hIqbdyTPxHe9GVA=";

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

        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            gofmt.enable = true;
            govet.enable = true;
            golangci-lint.enable = true;
          };
        };

      in
      {
        checks.integration = pkgs.buildGoModule {
          pname = "certificator-integration-tests";
          version = "0.0.0";
          src = ./.;

          vendorHash = "sha256-wqQj0P3cc9NX+gIFicGQUBi4+y5Fg/CuYPeFOwvJ8Jg=";

          subPackages = [ "cmd/certificatee" ];

          nativeBuildInputs = [
            pkgs.haproxy
            dataplaneapi
            pkgs.openssl
          ];

          doCheck = true;
          checkPhase = ''
            export HOME=$TMPDIR
            export GOCACHE=$TMPDIR/go-build
            export PATH=${pkgs.haproxy}/bin:${dataplaneapi}/bin:$PATH
            go test -tags=integration ./cmd/certificatee
          '';
        };

        devShells.default = pkgs.devshell.mkShell {
          name = "certificator";

          env = [
            { name = "CGO_ENABLED"; value = "0"; }
            { name = "GOTOOLCHAIN"; value = "local"; }
            { name = "GOPATH"; unset = true; }
            { name = "GOROOT"; value = "${pkgs.go}/share/go"; }
          ];

          packages = with pkgs; [
            go
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
            watchexec       # For test-watch command
          ];

          devshell.startup.git-hooks.text = pre-commit-check.shellHook;

          devshell.motd = ''
            {202}==========================================
              Certificator Development Environment
            =========================================={reset}

            Go version (from go.mod): ${goVersion}
            Go version (active):      $(go version | cut -d' ' -f3)
            HAProxy version:          $(haproxy -v | head -1)
            Data Plane API:           $(dataplaneapi --version 2>&1 | head -1 || echo 'available')

            $(type -p menu &>/dev/null && menu)
          '';

          commands = [
            {
              name = "build";
              help = "Build certificator and certificatee binaries";
              command = ''
                export BUILD_DIR="''${BUILD_DIR:-build}"
                echo "Building certificator in $BUILD_DIR..."
                mkdir -p "$BUILD_DIR"
                go build -o "$BUILD_DIR" ./cmd/certificator
                go build -o "$BUILD_DIR" ./cmd/certificatee
                echo "Build complete!"
              '';
            }
            {
              name = "run-tests";
              help = "Run unit tests";
              command = ''
                echo "Running tests..."
                go test -v ./...
              '';
            }
            {
              name = "test-coverage";
              help = "Run tests with coverage report";
              command = ''
                echo "Running tests with coverage..."
                go test -v -coverprofile=coverage.out ./...
                go tool cover -html=coverage.out -o coverage.html
                echo "Coverage report: coverage.html"
              '';
            }
            {
              name = "tidy";
              help = "Tidy go.mod dependencies";
              command = ''
                echo "Tidying dependencies..."
                go mod tidy
                go mod verify
              '';
            }
            {
              name = "check";
              help = "Run all checks (fmt, vet, lint, test)";
              command = ''
                echo "=== Running all checks ==="
                echo ""
                echo ">>> Checking gofmt..."
                GOFMT_OUTPUT=$(find . -name '*.go' -not -path './vendor/*' | xargs gofmt -l -s)
                if [ -n "$GOFMT_OUTPUT" ]; then
                  echo "gofmt found formatting issues in:"
                  echo "$GOFMT_OUTPUT"
                  echo ""
                  echo "Run 'gofmt -w -s .' to fix"
                  exit 1
                fi
                echo "gofmt: OK"

                echo ""
                echo ">>> Checking goimports..."
                GOIMPORTS_OUTPUT=$(find . -name '*.go' -not -path './vendor/*' | xargs goimports -l)
                if [ -n "$GOIMPORTS_OUTPUT" ]; then
                  echo "goimports found issues in:"
                  echo "$GOIMPORTS_OUTPUT"
                  echo ""
                  echo "Run 'goimports -w .' to fix"
                  exit 1
                fi
                echo "goimports: OK"

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
            }
            {
              name = "generate-tests";
              help = "Generate test stubs for a file";
              command = ''
                if [ -z "$1" ]; then
                  echo "Usage: generate-tests <file.go>"
                  exit 1
                fi
                gotests -all -w "$1"
              '';
            }
            {
              name = "test-watch";
              help = "Watch for changes and run tests";
              command = ''
                echo "Watching for changes and running tests..."
                watchexec -e go -- go test -v ./...
              '';
            }
            {
              name = "clean";
              help = "Clean build artifacts";
              command = ''
                BUILD_DIR="''${BUILD_DIR:-build}"
                echo "Cleaning build artifacts in $BUILD_DIR..."
                rm -f "$BUILD_DIR/certificator" "$BUILD_DIR/certificatee"
                rm -f coverage.out coverage.html
                go clean -cache -testcache
                echo "Clean complete!"
              '';
            }
          ];
        };
      }
    );
}
