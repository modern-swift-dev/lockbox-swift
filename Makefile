SHELL := /bin/bash

SCHEME ?= Lockbox
IOS_DESTINATION ?= platform=iOS Simulator,name=iPhone 17 Pro,OS=latest
TVOS_DESTINATION ?= platform=tvOS Simulator,name=Apple TV 4K (3rd generation),OS=latest
WATCHOS_DESTINATION ?= platform=watchOS Simulator,name=Apple Watch Series 11 (46mm),OS=latest
VISIONOS_DESTINATION ?= platform=visionOS Simulator,name=Apple Vision Pro,OS=latest


.PHONY: setup lint format documentation site-setup site-preview site-validate site-build \
	test test-swift test-examples test-linux test-macos \
	test-ios test-tvos test-watchos test-visionos test-apple test-all

setup:

	brew bundle install
	brew upgrade
	brew cleanup
	brew autoremove
	mint bootstrap
	lefthook install

lint:

	mint run --no-install realm/SwiftLint  --config .swiftlint.yml --quiet

format:

	mint run --no-install nicklockwood/SwiftFormat . --config .swiftformat --quiet
	mint run --no-install realm/SwiftLint  --config .swiftlint.yml --fix --quiet

documentation:

	bash Scripts/build-documentation.sh

site-setup:

	npm --prefix Website ci

site-preview: site-build

	bash Scripts/preview-site.sh

site-validate: site-setup

	npm --prefix Website run check
	bash Scripts/build-site.sh

site-build: site-setup

	bash Scripts/build-site.sh

test-macos:
	set -o pipefail && \
		swift test | mint run --no-install cpisciotta/xcbeautify -q

test-ios:
	set -o pipefail && \
	xcodebuild test \
		-scheme "$(SCHEME)" \
		-destination "$(IOS_DESTINATION)" | mint run --no-install cpisciotta/xcbeautify -q

test-tvos:
	set -o pipefail && \
	xcodebuild test \
		-scheme "$(SCHEME)" \
		-destination "$(TVOS_DESTINATION)" | mint run --no-install cpisciotta/xcbeautify -q

test-watchos:
	set -o pipefail && \
	xcodebuild test \
		-scheme "$(SCHEME)" \
		-destination "$(WATCHOS_DESTINATION)" | mint run --no-install cpisciotta/xcbeautify -q

test-visionos:
	set -o pipefail && \
	xcodebuild test \
		-scheme "$(SCHEME)" \
		-destination "$(VISIONOS_DESTINATION)" | mint run --no-install cpisciotta/xcbeautify -q

test-examples:
	set -o pipefail && \
	xcodebuild build \
		-project Examples/LockboxExample/LockboxExample.xcodeproj \
		-scheme LockboxExample \
		-destination "$(IOS_DESTINATION)" \
		CODE_SIGNING_ALLOWED=NO | mint run --no-install cpisciotta/xcbeautify -q

test: test-macos test-ios test-tvos test-watchos test-visionos test-examples
