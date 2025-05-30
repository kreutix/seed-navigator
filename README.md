# **SeedNavigator**

**SeedNavigator** is a minimal and interactive tool for exploring BIP39 seed phrases, deriving child seeds using BIP85, and generating Bitcoin addresses via BIP32. It allows users to navigate through hierarchical derivation paths, view child seed phrases, and inspect derived addresses in a user-friendly interface.

**Features**

- **BIP39 Seed Phrase Input**: Enter and set a root seed phrase.
- **BIP85 Child Seed Derivation**: View and load up to 10 child seed phrases derived from the current seed.
- **BIP32 Address Derivation**: Generate and display 10 Bitcoin addresses using a configurable derivation path (default: m/84'/0'/0'/0).
- **Path Navigation**: Easily navigate through derivation paths with a back button and a clear path display (e.g., root/, root/0/, root/0/1/).
- **Modern UI**: Built with React and styled with Tailwind CSS for a clean, responsive experience.

**Prerequisites**

Before using SeedNavigator, ensure you have the following installed:

- [Node.js](https://nodejs.org/) (v14 or later)
- [npm](https://www.npmjs.com/) (v6 or later) or [Yarn](https://yarnpkg.com/)

**Installation**

1. **Clone the repository**:bash
    
    ```bash
    git clone https://github.com/kreutix/seed-navigator.git
    cd seed-navigator
    ```
    
2. **Install dependencies**:bashOr, if using Yarn:bash
    
    ```bash
    npm install
    ```
    
    ```bash
    yarn install
    ```
    
3. **Run the application**:bashOr, with Yarn:bash
    
    ```bash
    npm start
    ```
    
    ```bash
    yarn start
    ```
    
4. **Open in your browser**:
    - The app will be available at http://localhost:3000.

**Usage**

1. **Enter a BIP39 Seed Phrase**:
    - On the initial screen, input a valid BIP39 seed phrase (12 or 24 words).
    - Click "Set Root Seed" to initialize the tool.
2. **Navigate Derivation Paths**:
    - The current path is displayed at the top (e.g., root/, root/0/).
    - Use the "Load" button next to each child seed phrase to navigate deeper into the derivation tree.
    - Use the "Back" button to return to the previous level.
3. **View Child Seed Phrases**:
    - 10 BIP85-derived child seed phrases are shown for the current path.
    - Each child can be loaded to explore further derivations.
4. **View Derived Addresses**:
    - 10 Bitcoin addresses are derived using the configurable BIP32 path.
    - You can adjust the derivation path (e.g., m/44'/0'/0'/0) to generate addresses for different purposes.
5. **Configure Derivation Path**:
    - Modify the derivation path in the input field to change the base path for address generation.

**Security Considerations**

- **Seed Phrase Security**: Never share your seed phrase with anyone. SeedNavigator is a local tool and does not transmit data, but always ensure your environment is secure.
- **Use for Testing**: For security reasons, it is recommended to use SeedNavigator with test seed phrases or in a secure, offline environment.
- **No Persistent Storage**: SeedNavigator does not store your seed phrase; it is only held in memory during the session.

**Contributing**

We welcome contributions to improve SeedNavigator! To contribute:

1. **Fork the repository**.
2. **Create a new branch** for your feature or bugfix.
3. **Submit a pull request** with a clear description of your changes.

Please ensure your code follows the project's coding standards and includes appropriate tests.

**Support**

If you encounter any issues or have questions, please:

- **Open an issue** on the [GitHub repository](https://github.com/kreutix/seed-navigator/issues).
- **Check the documentation** for more details (coming soon).

# Links

https://secretscan.org/Bech32