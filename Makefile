TESTS = tests/index.js
REPORTER = dot

# node-inspector ::
# --debug
# --debug-brk
test:
	@NODE_ENV=testing ./node_modules/.bin/mocha \
		--reporter $(REPORTER) \
		--timeout 600 \
		$(TESTS)