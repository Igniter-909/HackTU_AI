from pinecone import Pinecone
import os
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
import google.generativeai as genai
import torch
import numpy as np

load_dotenv()

class PineconeChatbot:
    def __init__(self):
        """Initialize the chatbot with Pinecone and Gemini"""
        try:
            # Initialize Pinecone
            api_key = os.getenv('PINECONE_API_KEY')
            index_name = os.getenv('PINECONE_INDEX_NAME')
            
            pc = Pinecone(api_key=api_key)
            self.index = pc.Index(index_name)
            
            # Initialize Gemini
            gemini_api_key = os.getenv('GEMINI_API_KEY')
            if not gemini_api_key:
                raise ValueError("GEMINI_API_KEY environment variable not set")
            
            # Configure Gemini with safety settings
            genai.configure(api_key=gemini_api_key)
            
            # Set up safety settings
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE",
                }
            ]
            
            # Initialize the model with safety settings
            generation_config = {
                "temperature": 0.3,
                "top_p": 1,
                "top_k": 1,
                "max_output_tokens": 2048,
            }
            
            self.model = genai.GenerativeModel(
                model_name='gemini-pro',
                generation_config=generation_config,
                safety_settings=safety_settings
            )
            
            # Initialize embedding model
            self.embedding_model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
            if torch.cuda.is_available():
                self.embedding_model = self.embedding_model.to('cuda')
            
            print("Chatbot initialized successfully!")
            
        except Exception as e:
            print(f"Error initializing chatbot: {str(e)}")
            raise

    def get_embedding(self, text: str) -> list:
        """Generate embedding for the query text"""
        try:
            with torch.no_grad():
                embedding = self.embedding_model.encode(text)
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

    def get_relevant_context(self, query: str, top_k: int = 5) -> str:
        """Retrieve relevant context from Pinecone"""
        try:
            query_embedding = self.get_embedding(query)
            
            if not isinstance(query_embedding, list):
                raise ValueError(f"Expected list, got {type(query_embedding)}")
            if not all(isinstance(x, (int, float)) for x in query_embedding):
                raise ValueError("All embedding values must be numbers")
            
            results = self.index.query(
                vector=query_embedding,
                top_k=top_k,
                include_metadata=True
            )
            
            context_parts = []
            for match in results['matches']:
                text = match['metadata'].get('text', '')
                source = match['metadata'].get('source', 'unknown')
                page = match['metadata'].get('page', 0)
                score = match['score']
                
                if score > 0.5:  # Only include relevant matches
                    context_parts.append(
                        f"[Source: {source}, Page: {page}]\n{text}\n"
                    )
            
            return "\n".join(context_parts)
            
        except Exception as e:
            print(f"Error retrieving context: {str(e)}")
            return ""

    def generate_response(self, query: str) -> str:
        """Generate a response using context and Gemini"""
        try:
            context = self.get_relevant_context(query)
            if not context:
                return "I don't have enough information to answer that question."
            
            prompt = f"""You are a cybersecurity expert assistant. Using only the provided context, answer the following question.
            If you cannot find the answer in the context, simply say "I don't have enough information to answer that question."
            Do not include any disclaimers or additional explanations.

            Context:
            {context}

            Question: {query}
            """
            
            try:
                response = self.model.generate_content(prompt)
                if response.text:
                    return response.text.strip()
                else:
                    return "I don't have enough information to answer that question."
            except Exception as e:
                print(f"Gemini error: {str(e)}")
                # Try with a simplified prompt
                simplified_prompt = f"Based on this context: {context}\n\nAnswer this question: {query}"
                response = self.model.generate_content(simplified_prompt)
                return response.text.strip() if response.text else "I don't have enough information to answer that question."
            
        except Exception as e:
            print(f"Error generating response: {str(e)}")
            return "I encountered an error while processing your question. Please try again."

def main():
    try:
        chatbot = PineconeChatbot()
        print("\nChatbot initialized! Type 'exit' to end the conversation.")
        
        while True:
            query = input("\nYou: ").strip()
            if query.lower() == 'exit':
                break
                
            response = chatbot.generate_response(query)
            print(f"\nAssistant: {response}")
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

if __name__ == "__main__":
    main() 