# AI Usage Disclosure

## 1. Which AI tools did you use?

I used ChatGPT (OpenAI) as an AI-assisted development and learning tool during the development of ReconSage Lite.

## 2. How did AI assist you?

ChatGPT assisted with understanding implementation approaches, planning the project structure, drafting and reviewing Python code, suggesting unit tests, troubleshooting errors, improving documentation, and explaining Git and command-line workflows.

I ran the commands, integrated the changes, reviewed the outputs, and made project decisions myself.

## 3. Which parts were generated or substantially suggested by AI?

AI assistance was used in the development of several parts of the project, including:

- Portions of the Python implementation for Nmap XML parsing, rule-based service analysis, report generation, and CLI handling.
- Suggestions for input validation, error handling, severity prioritisation, and report formatting.
- Unit-test cases and test coverage suggestions.
- Documentation and usage instructions in the README.

The final implementation was reviewed and tested as part of the development process. The project does not call an AI model or require an AI API at runtime. Detection and explanations are rule-based.

## 4. What mistakes, insecure suggestions, or incorrect assumptions did AI make?

During development, an overly strict XML validation approach was suggested that rejected an empty but valid Nmap XML scan. This was identified during testing and revised so that an empty scan can be parsed as an empty host list.

Some suggestions also needed adjustment to match the actual module names and project structure after files were renamed. I checked the imports and reran the tests after those changes.

I did not treat AI suggestions as automatically correct. I reviewed them and tested the resulting behaviour.

## 5. How did you manually validate the generated code or output?

I validated the project by:

- Running the unit-test suite; all 36 tests passed.
- Testing the parser and detection rules with the supplied synthetic Nmap XML samples.
- Running the CLI against single-host and multi-host sample scans.
- Checking that findings were prioritised as HIGH, MEDIUM, and LOW where applicable.
- Reviewing generated Markdown reports for host details, evidence, severity, and recommendations.
- Manually checking CLI help, custom output paths, and protection against overwriting an existing report.

Testing with a real Nmap-generated XML file is still being investigated separately; the first real scan file produced an incomplete or malformed XML parsing error and has not yet been counted as a successful validation.

## 6. What did you change after reviewing the AI-generated work?

I made and reviewed several changes during development, including:

- Removed the proposed AI explainer integration entirely. The final project uses deterministic, rule-based explanations and has no AI runtime dependency.
- Renamed the explanation module to `explanations.py` and updated its imports.
- Adjusted XML parser validation to support valid empty scan documents.
- Refined input validation, error handling, severity ordering, report formatting, and unique report filenames.
- Updated and reran the unit tests after implementation changes.

## 7. Which part of the final project can you confidently explain without AI assistance?

I can explain the complete processing workflow: how the tool reads Nmap XML, extracts host and port information, validates the parsed data, matches open services against predefined rules, assigns severity levels, sorts findings, and generates a Markdown report.

I can also explain the CLI arguments, project structure, rule-based detection limitations, and how the unit tests validate the individual components.
