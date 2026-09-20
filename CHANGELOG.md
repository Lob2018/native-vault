# Changelog


## Unreleased - 


📚 docs Doxygen

([fc07873a26d78d8](https://github.com/Lob2018/native-vault/commit/fc07873a26d78d8c5a2369949ababfd234272d6b))

✨ feat pom.xml, README.md, CHANGELOG.md: Add git-changelog-maven-plugin, CHANGELOG badge, and CHANGELOG
- README.md :
  - Add CHANGELOG shield badge.
  - Update Online Javadoc badge formatting.
- pom.xml :
  - Integrate se.bjurr.gitchangelog:git-changelog-maven-plugin v2.4.0 with custom Handlebars template and generate-resources execution phase.
- Tests pass.

([46504ddbd904c73](https://github.com/Lob2018/native-vault/commit/46504ddbd904c73ec196b5ea5750c04f57b40729))

♻️ refactor UML: Moved UML diagrams to .myresources/uml

([f86ef8fe03446cf](https://github.com/Lob2018/native-vault/commit/f86ef8fe03446cf348cd159255477577c92ffa07))

📚 docs Doxygen

([39796f6a8be4545](https://github.com/Lob2018/native-vault/commit/39796f6a8be4545e10d11b611afa7cd7f3cfea1a))

📚 docs README.md: Format architecture section heading level and adjust diagram list items

([e5e1801ac5e8c65](https://github.com/Lob2018/native-vault/commit/e5e1801ac5e8c65bacfdbbd4e8456093cf4f1506))

✨ feat pom.xml, README.md, class.puml, usecase.puml: Add UML architecture documentation and PlantUML build generation
- Add PlantUML maven execution configuration in pom.xml to generate SVG diagrams during build.
- Create class.puml and usecase.puml schemas under .myresources/uml.
- Update README.md to integrate the new Architecture (UML) section with raw image links.
- Tests pass.

([72831610d946c75](https://github.com/Lob2018/native-vault/commit/72831610d946c75aa0f72b0cbf75a99dab45ab6e))

📚 docs Doxygen

([c95d332662ee245](https://github.com/Lob2018/native-vault/commit/c95d332662ee2457e52c11d9b03afe5f4e1f7f4f))

📚 docs README.md: Update security warning to CAUTION block specifying key concatenation

([e289213015b7d56](https://github.com/Lob2018/native-vault/commit/e289213015b7d56536aacecf05308d1a01acb715))

📚 docs README.md: Update security warning to CAUTION block explaining namespace isolation mechanics

([0b081fda7aa78e5](https://github.com/Lob2018/native-vault/commit/0b081fda7aa78e590b305cc6ba671d7ccb31a184))

♻️ refactor NativeVault: remove String overload methods to enforce char[] usage for keys and secrets
- NativeVault:
    - Remove String parameter overloads for setSecret, getSecret, removeSecret, and hasSecret.
    - Remove unused Apache Commons Lang StringUtils import.
- NativeVaultTest:
    - Refactor test cases and teardown logic to use char[] buffers exclusively with proper zero-filling.
    - Remove string-based test methods and update test class javadoc.
- Tests pass.

([41a3c99f061597f](https://github.com/Lob2018/native-vault/commit/41a3c99f061597fbb8e0426ee5ac8c2bbd28e990))

✨ feat NativeVault: Support namespace isolation, enhanced memory hygiene, unified key and secret size validation
- LinuxKeyringStrategy:
    - Add schemaName parameter to constructor and initialize schemaSegment dynamically.
    - Refactor strategy methods to use validateKey, validateSecret, and zeroFill.
    - Implement secure null-terminated string length calculation for retrieve and exists.
- MacKeychainStrategy:
    - Add namespace parameter to constructor and clone array.
    - Implement namespaced key concatenation using concatNamespaceAndKey in store, retrieve, delete, and exists.
    - Refactor native pointer handling and release logic with zero-filling.
- WindowsCredentialManagerStrategy:
    - Add namespace parameter to constructor and clone array.
    - Integrate concatNamespaceAndKey for target names in store, retrieve, delete, and exists.
    - Apply centralized secret and key length validations.
- AbstractVaultStrategy:
    - Add MAX_KEY_BYTE_SIZE and platform-specific secret size constants.
    - Implement validateKey, validateSecret, and overloaded zeroFill methods.
    - Add concatNamespaceAndKey helper method with validation.
- NativeVault:
    - Update constructor to require a namespace character array.
    - Remove static initialization and replace with instance-level strategy and verification state.
    - Update getIntegrityTestKey method name.
- NativeVaultTest:
    - Pass namespace parameter to NativeVault instantiation in setUp.
    - Add unit tests for over-limit keys and secrets.
    - Update integrity check key method reference.
- README.md:
    - Update code examples to use the new namespace-aware NativeVault constructor.
    - Adjust buffer cleanup and variable scopes in documentation.
- Tests pass.

([bfbedc74f5be376](https://github.com/Lob2018/native-vault/commit/bfbedc74f5be376c5f8f88da509568e5ed1fc540))

♻️ refactor CrossPlatformVaultLoader: Refactor native symbol lookup resolution
- CrossPlatformVaultLoader:
     - Extract symbol lookup resolution logic into a private helper method.
     - Add Javadoc documentation for the new resolution helper.
     - Optimize symbol search flow and clean up imports.
- Tests pass.

([0bee8a74ecb1e1d](https://github.com/Lob2018/native-vault/commit/0bee8a74ecb1e1d048c60df9e9cc6039dded27d0))

♻️  refactor WindowsCredentialManagerStrategy: Refactor native Windows credential structure mapping
- NativeCredentialRecord:
     - Add private static record for mapping native CREDENTIAL structures.
     - Declare static VarHandles for layout fields.
     - Implement fromSegment mapping method.
- WindowsCredentialManagerStrategy:
     - Replace manual offset lookups with static VarHandles for store, retrieve, and delete logic.
     - Optimize retrieve method to decode UTF-16LE directly from MemorySegment via ByteBuffer.
     - Centralize resource cleanup and blob zero-filling in freeCredential method.
- Tests pass.

([cbae1c9c1d8c1b6](https://github.com/Lob2018/native-vault/commit/cbae1c9c1d8c1b672a4b0a1470d334f8a0d62b7d))

📝 style README.md: Run automatic code formatter

([7c39d704bd4815f](https://github.com/Lob2018/native-vault/commit/7c39d704bd4815fdb85cec31e3a5454b05980ed0))

📚 docs README: improve readability and naming in usage demo
- README.md: Format long character array declarations across multiple lines.
- README.md: Simplify action comments and rename lambda parameter to rawSecret.
- Tests pass.

([e61ce47a23f43af](https://github.com/Lob2018/native-vault/commit/e61ce47a23f43af71e1eaa94a895f77cb2e7bcd8))

📚 docs README: enhance memory hygiene safety in usage demo with try-finally block
- README: Wrap secret processing in try-finally block to guarantee zero-fill memory cleanup on retrieved character arrays.
- README: Import or use direct Arrays.fill calls cleanly.
- Tests pass.

([f37991cb2285ffe](https://github.com/Lob2018/native-vault/commit/f37991cb2285ffe4126ed622e60c4b36e268c3f7))

♻️ refactor CrossPlatformVaultLoader, AbstractVaultStrategy, WindowsCredentialManagerStrategy: standardize validation exceptions and memory segment allocation
- CrossPlatformVaultLoader: Replace NullPointerException with IllegalArgumentException for descriptor validation.
- AbstractVaultStrategy: Uniformize parameter checks using Objects.isNull and IllegalArgumentException.
- WindowsCredentialManagerStrategy: Remove redundant keySegment method and leverage inherited allocateSegment.
- Tests pass.

([765bae1fb1bc954](https://github.com/Lob2018/native-vault/commit/765bae1fb1bc9541187cd10da7bbaf0f2de69a42))

🐛 fix WindowsCredentialManagerStrategy: decode retrieved credential blob using UTF-16LE instead of UTF-8
- WindowsCredentialManagerStrategy : update retrieve() method to decode binary blob with UTF-16LE matching the storage encoding format
- Tests pass.

([896fa6d0586f19e](https://github.com/Lob2018/native-vault/commit/896fa6d0586f19e2800e4bcab8400c481a0bea91))

📚 docs Doxygen

([da004b66441bfa2](https://github.com/Lob2018/native-vault/commit/da004b66441bfa2f5c439450b6be81067df13bb9))

📚 docs VaultStrategy, NativeVault: Add JavaDoc

([ca4ec77f84b4e69](https://github.com/Lob2018/native-vault/commit/ca4ec77f84b4e6928ed69b3f89ddedd51c50c96f))

♻️ refactor NativeVault, AbstractVaultStrategy, LinuxKeyringStrategy, MacKeychainStrategy, VaultStrategy, WindowsCredentialManagerStrategy: architectural cleanup and windows credential encoding fix
- NativeVault : move OS detection logic into facade
- AbstractVaultStrategy : introduce abstract base class for shared memory helpers
- LinuxKeyringStrategy, MacKeychainStrategy, WindowsCredentialManagerStrategy : extend AbstractVaultStrategy and adjust class visibility
- VaultStrategy : convert interface to pure contract without default helper methods
- WindowsCredentialManagerStrategy : enforce UTF-16LE encoding and remove redundant buffer size allocation
- Tests pass.

([059d82952e7b254](https://github.com/Lob2018/native-vault/commit/059d82952e7b254f427b9753cad60f806bc9a34f))

📚 docs Doxygen

([9be9ffffc2ab6b8](https://github.com/Lob2018/native-vault/commit/9be9ffffc2ab6b8164352cb2ec7aac4e902abb00))

♻️ refactor VaultStrategy: Check NPE for charset in allocateSegment method
- Tests pass

([155d4d7af0fe9e3](https://github.com/Lob2018/native-vault/commit/155d4d7af0fe9e38592128a3d855963411be9cdb))

✨ feat NativeVault,NativeVaultException,LinuxKeyringStrategy,MacKeychainStrategy,VaultStrategy,WindowsCredentialManagerStrategy: Refactor native vault strategy interfaces to handle char arrays and enforce strict zero-fill memory sanitization
- NativeVault: Remove redundant segment allocation wrappers and delegate raw secret management directly to strategies.
- NativeVaultException: Add single-parameter constructor for string messages.
- LinuxKeyringStrategy: Refactor store, retrieve, and delete methods to utilize safer char array signatures with guaranteed off-heap buffer cleanup.
- MacKeychainStrategy: Implement robust memory sanitization and safe pointer reinterpretation across all OS keychain operations.
- VaultStrategy: Update interface contract from MemorySegment to char[] for secrets, and provide default security utilities.
- WindowsCredentialManagerStrategy: Secure native credential blobs and buffers with comprehensive finalization blocks.
- Tests pass.

([0a48af4d8b35ad3](https://github.com/Lob2018/native-vault/commit/0a48af4d8b35ad3e10f6e1e173efffb472b1faac))

✨ feat VaultStrategy, NativeVault, and strategies: migrate from MemorySegment to char arrays and remove AutoCloseable lifecycle
- README.md: update usage example to reflect removal of AutoCloseable and add initialization comment
- NativeVault: remove AutoCloseable interface, arena field, and close method, and add thread-safe synchronization for integrity check
- CrossPlatformVaultLoader: fix exception message formatting consistency
- LinuxKeyringStrategy: update store and retrieve signatures to use char arrays and confined arenas
- MacKeychainStrategy: update store and retrieve signatures to use char arrays and confined arenas
- VaultStrategy: adjust interface method signatures to eliminate arena parameter requirements
- WindowsCredentialManagerStrategy: update store and retrieve methods to handle char arrays and internal confined arenas
- NativeVaultTest: remove vault close calls in tearDown and add test for secret updates
- Tests pass.

([19e3cd9257f68cf](https://github.com/Lob2018/native-vault/commit/19e3cd9257f68cfccde21f1a239dd2234c4c2160))

🔧 chore .snyk: Add Snyk configuration file

([ee166d20d0ac7d2](https://github.com/Lob2018/native-vault/commit/ee166d20d0ac7d28a40d81acc5e4b7aede39013b))

📚 docs Doxygen

([0e8a9a0e1120a8f](https://github.com/Lob2018/native-vault/commit/0e8a9a0e1120a8fe90dcb14ec1339c7a196c80e9))

✨ feat NativeVault, LinuxKeyringStrategy, WindowsCredentialManagerStrategy, VaultStrategy, NativeVaultException, module-info, NativeVaultTest: Enhance exception handling, memory safety, and thread safety
- NativeVault:
	- Update javadoc and usage example to catch NativeVaultException and LinkageError.
	- Implement static initialization with AtomicReference and boolean verification for strategies.
	- Switch to Arena.ofShared() for thread safety and update method signatures to throw NativeVaultException.
- LinuxKeyringStrategy:
	- Add NativeVaultException to strategy method signatures and handle native failures gracefully.
	- Secure byte buffers and memory segments with proper zero-filling.
- WindowsCredentialManagerStrategy:
	- Add NativeVaultException to strategy method signatures and handle native errors.
	- Implement secure keySegment allocation and robust null pointer checks for native handles.
- VaultStrategy:
	- Propagate NativeVaultException across all interface method declarations.
- NativeVaultException:
	- Change superclass from RuntimeException to Exception.
- module-info:
	- Export fr.softsf.vault.exception package.
- NativeVaultTest:
	- Adapt setup, teardown, and unit tests to handle NativeVaultException.
- Tests pass.

([304a50af398308b](https://github.com/Lob2018/native-vault/commit/304a50af398308b5f282562cb465824e84469f9f))

📚 docs Doxygen

([5606cef3c50ef79](https://github.com/Lob2018/native-vault/commit/5606cef3c50ef79851768b37ba7886a779cd2b1f))

♻️ refactor NativeVault, CrossPlatformVaultLoader: harmonize null checks and update Javadocs
- NativeVault :
	- Replace Objects.isNull with Objects.requireNonNull for arena and segment validation
	- Update constructor and method Javadocs to document NullPointerException
- CrossPlatformVaultLoader :
	- Replace Objects.isNull with Objects.requireNonNull for descriptor validation
	- Update Javadoc to document NullPointerException and UnsatisfiedLinkError
- Tests pass.

([36e664ef06acc90](https://github.com/Lob2018/native-vault/commit/36e664ef06acc905f1b166da13378d8b35a34bd8))

📚 docs README.md: Update native vault project introduction with explicit library context

([63530043b664cde](https://github.com/Lob2018/native-vault/commit/63530043b664cde1dfc7bf2ef5ebc791ce41abc3))

📚 docs README.md: Add lock emoji to main title

([c089cf839ef2317](https://github.com/Lob2018/native-vault/commit/c089cf839ef23170ab047f93e5a3ecf3e5dd56dc))

🐛 fix README.md: Add empty line before session note to prevent markdown table rendering issues

([0d2897ae590a775](https://github.com/Lob2018/native-vault/commit/0d2897ae590a77560f66cb395296e66d274f12a3))

📚 docs README.md: Add active desktop session note with HTML tag for secure storage providers table

([986be4d7b44760d](https://github.com/Lob2018/native-vault/commit/986be4d7b44760d6b25a84fbc512a5b0f9078e72))

📚 docs NativeVault: Update Javadoc documentation and configuration files
- NativeVault.java:
	- Add Javadoc documentation for class and methods
- Doxyfile:
	- Update configuration to use README.md as mainpage and include it in inputs
- README.md:
	- Enhance with online Javadoc badge and updated usage example with secure char arrays
- mainpage.dox:
	- Remove obsolete mainpage.dox file
- Tests pass.

([28b956916bb4ec1](https://github.com/Lob2018/native-vault/commit/28b956916bb4ec132f6bdd15183309e3c933b5cc))

📚 docs README.md: Add clickable Online Javadoc heading

([fb7f1484c9256a4](https://github.com/Lob2018/native-vault/commit/fb7f1484c9256a4f5a3f19a24df831c1c328c036))

📚 docs Doxygen

([12d89df909d3f74](https://github.com/Lob2018/native-vault/commit/12d89df909d3f74132396017e6a1953a7d0fea86))

♻️ refactor: LinuxKeyringStrategy, VaultStrategy, WindowsCredentialManagerStrategy: Add explicit null and argument validation
-LinuxKeyringStrategy:
	-Add input parameter checks and NPE validation for key, secretData, and arena
-VaultStrategy:
	-Document expected exceptions in interface Javadoc
-WindowsCredentialManagerStrategy:
	-Add input parameter checks and NPE validation for key, secretData, and arena
-Tests pass.

([977ae3797308779](https://github.com/Lob2018/native-vault/commit/977ae37973087792872f51794302dc28df68d70c))

📚 docs LinuxKeyringStrategy, WindowsCredentialManagerStrategy: Add official API reference links to Javadocs
- Add Libsecret API Reference and GLib Reference Manual links to LinuxKeyringStrategy.
- Add Wincred.h Win32 API Reference link to WindowsCredentialManagerStrategy.
- Tests pass.

([da2271af5878aae](https://github.com/Lob2018/native-vault/commit/da2271af5878aaee541f6d166d4519d038c79473))

♻️ refactor README.md, NativeVault, LinuxKeyringStrategy, WindowsCredentialManagerStrategy: Improve native initialization safety and documentation
- README.md :
	- Update usage example with defensive try-catch error handling block
- NativeVault :
	- Add Javadoc note regarding static initialization and try-catch requirements
- LinuxKeyringStrategy :
	- Extract ATTRIBUTES constant and update layout path element reference
	- Wrap static initialization in defensive try-catch block preserving critical JVM errors
- WindowsCredentialManagerStrategy :
	- Wrap static initialization in defensive try-catch block preserving critical JVM errors
- Tests pass.

([a1dee5a1425a527](https://github.com/Lob2018/native-vault/commit/a1dee5a1425a527d5f24ef6389488ab135d60b61))

✨ feat .sdkmanrc, runConfigurations: Add SDKMAN configuration and platform-specific IDE run configurations
- .sdkmanrc :
	- Define Java 25 and Maven 3.9.16.
- .idea/runConfigurations/Verify (Linux).xml :
	- Create Linux verify run configuration with SDKMAN environment variables.
- .idea/runConfigurations/Verify (Windows).xml :
	- Rename existing verify configuration for Windows compatibility.
- .run/Spotbugs GUI (Linux).run.xml :
	- Create Linux Spotbugs GUI run configuration with SDKMAN environment variables.
- .run/Spotbugs GUI (Windows).run.xml :
	- Rename existing Spotbugs GUI configuration for Windows compatibility.
- Tests pass.

([65555f88ea3930f](https://github.com/Lob2018/native-vault/commit/65555f88ea3930f491b4353b59aab36db77550f0))

♻️ refactor LinuxKeyringStrategy: Refactor LinuxKeyringStrategy for SecretSchema memory layout and native bindings
- Define SECRET_SCHEMA_LAYOUT and SECRET_SCHEMA_ATTRIBUTE_LAYOUT constants.
- Add Javadoc to keySegment helper method.
- Update store, retrieve, delete, and exists to use schema segments.
- Tests pass.

([78708dd14285051](https://github.com/Lob2018/native-vault/commit/78708dd1428505149d1d7559704df90479d6ebf5))

🛠️ build: pom.xml, README.md: Update compiler release and documentation for Java 25 requirement
- Update maven.compiler.release property to 25 in pom.xml.
- Update JDK prerequisite to 25 in README.md.
- Tests pass.

([b8b5ea295b77b8f](https://github.com/Lob2018/native-vault/commit/b8b5ea295b77b8f50bd9020704eb510f41d70672))

✨ feat pom.xml: Add Spotless configuration
- Configure Spotless plugin for source code formatting
- Tests pass.

([89f924d78757571](https://github.com/Lob2018/native-vault/commit/89f924d78757571cdc302645665814821c7ad316))

📚 docs README.md: Document key collision risk and update usage example with unique package-prefixed key variable
- Document OS keychain collision risk with a warning callout in README.md.
- Refactor code snippet to use a dedicated unique package-prefixed key variable to avoid keychain collisions.
- Tests pass.

([db528db9e311324](https://github.com/Lob2018/native-vault/commit/db528db9e3113240eeae6b8ebc586a054204d26c))

📚 docs README: Add target environment constraints
- Document desktop application requirement and headless server incompatibility
- Tests pass.

([370e37fc44eb6df](https://github.com/Lob2018/native-vault/commit/370e37fc44eb6df32aed80d9a572f9abc3b1561a))

🔧 chore Verify.xml: Rename IntelliJ run configuration from Package to Verify and update goal to verify
- Update Maven goal from package to verify in run configuration
- Tests pass.

([5bac29d1084a292](https://github.com/Lob2018/native-vault/commit/5bac29d1084a292dcd354966a713badc466fd919))

📚 docs: README, NativeVault: Document upsert behavior for setSecret method
- NativeVault : Update Javadoc for string and char[] overloads
- README : Clarify upsert behavior in sample code
- Tests pass.

([599aa48b20053e0](https://github.com/Lob2018/native-vault/commit/599aa48b20053e0e85e2aad637d2c4842cd08d16))

🔧 chore pom.xml: Set version to 0.1.0
- Downgrade project version to 0.1.0 in pom.xml
- Tests pass.

([fb4ab4e443e346e](https://github.com/Lob2018/native-vault/commit/fb4ab4e443e346eb87304007d80ae3a9431ab79c))

📚 docs README.md: Mark project as in development
- Add status badge and warning callout to README.md
- Tests pass.

([1565959cabda2f9](https://github.com/Lob2018/native-vault/commit/1565959cabda2f95126dfe08f6a744614b1579e8))

🛠️ build _template__of_JUnit.xml, NOTICE.txt, README.md, pom.xml: Finalize documentation, NOTICE compliance and Java 22 release configuration
 - NOTICE.txt : MIT attribution for conceptual inspiration
 - README.md : update with unified structure and precise technical description
 - pom.xml : setting maven.compiler.release to 22
 - Tests pass.

([59589f89d09c888](https://github.com/Lob2018/native-vault/commit/59589f89d09c888520e500f4ca7b369972de2c87))

♻️ refactor NativeVault, NativeVaultTest: Centralize integrity test key and update test suite
- NativeVault: Define INTEGRITY_TEST_KEY constant and getIntegrityTestKeyChar helper method, and update IntegrityHolder to use them.
- NativeVaultTest: Refactor test cases to use the centralized integrity key and add memory sanitation with Arrays.fill.
- Tests pass.

([b1caaa1f819ae75](https://github.com/Lob2018/native-vault/commit/b1caaa1f819ae75db5cfa409a38650b53ed6e086))

✅ test NativeVaultTest: Update tests to assert boolean return values for String-based setSecret and removeSecret operations :
- Tests pass.

([5dfc84cfda84461](https://github.com/Lob2018/native-vault/commit/5dfc84cfda844613b26d9f74bd9582951c263354))

♻️ refactor NativeVault, LinuxKeyringStrategy, MacKeychainStrategy, WindowsCredentialManagerStrategy, VaultStrategy: Cleanup runConfigurations, migrate strategy package, remove logging for silent failure contract, and package-private strategy classes :
- Package.xml : Add Maven package run configuration.
- _template__of_JUnit.xml : Remove obsolete JUnit configuration template.
- NativeVault : Remove logger instance and calls, update methods to return boolean execution status, and remove redundant strategy null check in integrity validation.
- LinuxKeyringStrategy : Move to strategy package, make class package-private, add Glib g_free cleanup and error handling.
- MacKeychainStrategy : Move to strategy package, make class package-private, add CoreFoundation CFRelease cleanup and error handling.
- VaultStrategy : Move to strategy package, remove logger and logging statements.
- WindowsCredentialManagerStrategy : Move to strategy package, make class package-private, remove error logging.
- module-info : Remove redundant java.base requirement.
- Tests pass.

([f30d123f5f0783c](https://github.com/Lob2018/native-vault/commit/f30d123f5f0783c52be177c610cc847706bb725b))

✅ test NativeVaultExceptionTest: Add unit tests for exception handling
- NativeVaultExceptionTest:
    - Add unit tests verifying constructor arguments, detail message mapping, and cause propagation.
    - Implement assertions checking exception state.
- Tests pass.

([94f98c3d7358ebb](https://github.com/Lob2018/native-vault/commit/94f98c3d7358ebb5a008b9409579796365e6238b))

♻️ refactor NativeVault, WindowsCredentialManagerStrategy, pom, runConfigurations: Refactor native vault integrity check to lazy initialization and update build/test configurations
- Tests pass.

([b8577f4df85ffc5](https://github.com/Lob2018/native-vault/commit/b8577f4df85ffc535f19ab083e70fc6926a557f8))

♻️ refactor CrossPlatformVaultLoader: Streamline Advapi32 library lookup string concatenation
- CrossPlatformVaultLoader: Remove redundant lowercase evaluation and inline libraryFile variable
- Tests pass.

([67736690568b237](https://github.com/Lob2018/native-vault/commit/67736690568b237e3c9df12adfe37c6ee3bc41da))

✨ feat NativeVault, CrossPlatformVaultLoader, LinuxKeyringStrategy, MacKeychainStrategy, VaultStrategy, WindowsCredentialManagerStrategy, module-info, pom.xml, NativeVaultTest: Implement Windows-ready native vault library using Java 25 FFM API with other OS implementations remaining to be developed
- NativeVault: Implement security facade with char array buffer handling, arena lifecycle management, and static CRUD verification
- CrossPlatformVaultLoader: Configure native function symbol lookup and FFM linker downcall handling across platforms
- LinuxKeyringStrategy: Add libsecret implementation for Linux keyring operations with secure memory allocation [Status: Pending Development]
- MacKeychainStrategy: Add Security framework implementation for macOS keychain storage and retrieval [Status: Pending Development]
- VaultStrategy: Define polymorphic interface for OS-native credential management and platform detection logic
- WindowsCredentialManagerStrategy: Add Advapi32 implementation for Windows credential management with structure layout mapping [Status: Operational]
- module-info: Define module descriptor exporting vault packages and requiring java.base
- pom.xml: Configure Maven project for Java 25, native access argument, and JUnit 5 dependencies
- NativeVaultTest: Add unit tests following Given-When-Then convention for lifecycle and CRUD operations
- Tests pass.

([6a1aa085dd806b3](https://github.com/Lob2018/native-vault/commit/6a1aa085dd806b3bb2f3eb0d500fd28ebf6ca8d4))

♻️ refactor .gitignore: Update ignore patterns for project and IDE files

([ee76d5fb99822eb](https://github.com/Lob2018/native-vault/commit/ee76d5fb99822eb9cf5443ad622edbd6835ac7a2))

♻️ refactor .gitignore: Exclude target, .idea and out folders

([31a8e74a670363c](https://github.com/Lob2018/native-vault/commit/31a8e74a670363c1c2b273233b1178a2ce3ad3ff))

Initial commit

([621a6dd4a3cb2d0](https://github.com/Lob2018/native-vault/commit/621a6dd4a3cb2d01b487cc533186a8577911a24c))
