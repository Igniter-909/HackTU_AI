import React from 'react';
import Chatbot from './components/Chatbot';

function App() {
  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="container mx-auto">
        <h1 className="text-3xl font-bold text-center mb-8">Cybersecurity Assistant</h1>
        <Chatbot />
      </div>
    </div>
  );
}

export default App; 