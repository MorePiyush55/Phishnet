#!/bin/bash

# PhishNet Frontend Setup Script

echo "🛡️  PhishNet Frontend Setup"
echo "========================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18+ is required. Current version: $(node --version)"
    exit 1
fi

echo "✅ Node.js $(node --version) detected"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed."
    exit 1
fi

echo "✅ npm $(npm --version) detected"

# Navigate to frontend directory
cd "$(dirname "$0")"

echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOL
# PhishNet Frontend Environment Variables
REACT_APP_API_URL=http://localhost:8000
EOL
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Make sure the backend server is running on port 8000"
echo "2. Start the development server: npm run dev"
echo "3. Open http://localhost:3000 in your browser"
echo ""
echo "Demo credentials:"
echo "  - Admin: admin/admin"
echo "  - Analyst: analyst/analyst"
echo ""
echo "Happy coding! 🚀"
