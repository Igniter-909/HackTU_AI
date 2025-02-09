from pathlib import Path

def setup_directories():
    """Create necessary directories for the application"""
    # Get the root directory
    root_dir = Path(__file__).parent.parent.parent.parent
    
    # Create directories
    directories = [
        root_dir / "models" / "pdfs",
        root_dir / "models" / "books",
        root_dir / "models" / "aptDetection",
        root_dir / "models" / "phishingDetection"
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {directory}")

if __name__ == "__main__":
    setup_directories() 