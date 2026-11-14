DIST := $(CURDIR)/dist
export VM

.PHONY: debug release test clean

debug:
	xcodebuild -project untcc.xcodeproj -scheme untcc -configuration Debug \
		-destination 'generic/platform=macOS' CONFIGURATION_BUILD_DIR="$(DIST)/Debug" build

release:
	xcodebuild -project untcc.xcodeproj -scheme untcc -configuration Release \
		-destination 'generic/platform=macOS' CONFIGURATION_BUILD_DIR="$(DIST)/Release" build
	shasum -a 256 "$(DIST)/Release/untcc"

test:
	./tests.sh "$$VM"

clean:
	rm -rf "$(DIST)"
