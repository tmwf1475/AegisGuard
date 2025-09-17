from langchain.text_splitter import RecursiveCharacterTextSplitter
import json
import re

# Load vulnerability data
with open("data/ms17-010_data.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Set text splitting parameters
splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)

# Define keywords to keep (relevant to vulnerabilities)
include_keywords = [
    "CVE", "vulnerability", "security update", "exploit",
    "remote code execution", "Microsoft Windows", "SMBv1"
]

# Define keywords to exclude (irrelevant content)
exclude_keywords = [
    "navigation", "privacy policy", "terms of use", "acknowledgments",
    "Visualizations", "Legal Disclaimer", "Vulnerability Search", 
    "CPE Search", "Expand or Collapse", "Upgrade to Microsoft Edge",
    "CVE Modified by Microsoft Corporation", "CVE Modified by CVE"
]

def clean_text(text):
    """ Cleans text by removing special characters and formatting errors """
    text = re.sub(r'\s+', ' ', text)  # Remove extra spaces and new lines
    text = text.replace("â", "’")  # Fix encoding errors
    return text.strip()

def is_relevant(text):
    """ Determines whether the text is relevant to vulnerabilities """
    return any(keyword.lower() in text.lower() for keyword in include_keywords) and \
           not any(keyword.lower() in text.lower() for keyword in exclude_keywords)

# Process text
filtered_texts = []
for source, content in data.items():
    # Check each line and remove irrelevant content
    sentences = content.split("\n")
    relevant_sentences = [clean_text(sentence) for sentence in sentences if is_relevant(sentence)]
    filtered_texts.append("\n".join(relevant_sentences))

# Split text
split_texts = []
for text in filtered_texts:
    split_texts.extend(splitter.split_text(text))

# Remove duplicate text (simple check for exact duplicates)
unique_texts = list(set(split_texts))

# Save cleaned text
with open("data/ms17-010_chunks.json", "w", encoding="utf-8") as f:
    json.dump(unique_texts, f, indent=4, ensure_ascii=False)

print(f"Processing complete, generated {len(unique_texts)} refined text segments!")
