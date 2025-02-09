from pinecone import Pinecone
import os
from dotenv import load_dotenv
from pathlib import Path
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
import torch
import numpy as np
from tqdm import tqdm

load_dotenv()

class DocumentIndexer:
    def __init__(self):
        """Initialize document indexer with Pinecone and embeddings model"""
        try:
            # Initialize Pinecone
            api_key = os.getenv('PINECONE_API_KEY')
            index_name = os.getenv('PINECONE_INDEX_NAME')
            
            pc = Pinecone(api_key=api_key)
            self.index = pc.Index(index_name)
            
            # Initialize embedding model
            self.model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
            if torch.cuda.is_available():
                self.model = self.model.to('cuda')
            
            print("Document indexer initialized successfully!")
            
        except Exception as e:
            print(f"Error initializing indexer: {str(e)}")
            raise

    def get_embedding(self, text: str) -> list:
        """Generate embedding for text"""
        try:
            with torch.no_grad():
                embedding = self.model.encode(text)
                if torch.is_tensor(embedding):
                    embedding = embedding.cpu().numpy()
                if isinstance(embedding, np.ndarray):
                    embedding = embedding.tolist()
                if isinstance(embedding, list) and isinstance(embedding[0], list):
                    embedding = embedding[0]
                return embedding
        except Exception as e:
            print(f"Error generating embedding: {str(e)}")
            raise

    def load_pdfs(self):
        """Load PDFs from the Data directory"""
        root_dir = Path(__file__).parent.parent.parent.parent
        data_dir = root_dir / "Data"
        
        if not data_dir.exists():
            print(f"Creating directory: {data_dir}")
            data_dir.mkdir(parents=True, exist_ok=True)
        
        pdf_files = list(data_dir.glob("**/*.pdf"))
        print(f"\nFound {len(pdf_files)} PDF files:")
        for pdf in pdf_files:
            print(f"- {pdf.name}")
        
        if not pdf_files:
            return []
        
        documents = []
        for pdf_path in pdf_files:
            try:
                print(f"\nLoading {pdf_path.name}...")
                loader = PyPDFLoader(str(pdf_path))
                docs = loader.load()
                for doc in docs:
                    doc.metadata['source'] = pdf_path.name
                documents.extend(docs)
                print(f"Successfully loaded {len(docs)} pages from {pdf_path.name}")
            except Exception as e:
                print(f"Error loading {pdf_path.name}: {str(e)}")
                continue
        
        return documents

    def split_documents(self, documents):
        """Split documents into chunks"""
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=50
        )
        chunks = text_splitter.split_documents(documents)
        print(f"\nCreated {len(chunks)} text chunks")
        return chunks

    def index_documents(self, chunks, batch_size=32):
        """Index document chunks in Pinecone"""
        total_chunks = len(chunks)
        print(f"\nIndexing {total_chunks} chunks in Pinecone...")
        
        for i in tqdm(range(0, total_chunks, batch_size)):
            batch = chunks[i:min(i + batch_size, total_chunks)]
            
            try:
                # Prepare batch
                ids = [f"chunk_{i + j}" for j in range(len(batch))]
                texts = [chunk.page_content for chunk in batch]
                metadatas = [{
                    'text': chunk.page_content,
                    'source': chunk.metadata.get('source', 'unknown'),
                    'page': chunk.metadata.get('page', 0)
                } for chunk in batch]
                
                # Generate embeddings
                embeddings = [self.get_embedding(text) for text in texts]
                
                # Create vectors
                vectors = list(zip(ids, embeddings, metadatas))
                
                # Upsert to Pinecone
                self.index.upsert(vectors=vectors)
                
            except Exception as e:
                print(f"Error processing batch {i//batch_size + 1}: {str(e)}")
                continue
            
            # Clear some memory
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

def main():
    try:
        # Initialize indexer
        indexer = DocumentIndexer()
        
        # Load documents
        print("\nLoading documents...")
        documents = indexer.load_pdfs()
        if not documents:
            print("No documents found to process.")
            return
        
        # Split into chunks
        print("\nSplitting documents...")
        chunks = indexer.split_documents(documents)
        
        # Index in Pinecone
        print("\nIndexing in Pinecone...")
        indexer.index_documents(chunks)
        
        print("\nIndexing completed successfully!")
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

if __name__ == "__main__":
    main()
