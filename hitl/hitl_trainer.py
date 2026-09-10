"""
Team 3 - HITL backend / learning mechanism

Flow:
  UNKNOWN COMMAND -> MiniLM similarity -> Suggestions shown ->
  ADMIN CHOOSES -> auditor.train_command() saves it -> learned.json updated ->
  Re-run parse() to confirm recognition

This script does NOT write learned.json directly - it calls train_command()
from auditor.py, so there is only one place that ever writes that file.
"""

from sentence_transformers import SentenceTransformer, util
from auditor import train_command, VALID_CATEGORIES  # single source of truth

# Load the embedding model once - this is NOT a generative LLM,
# it just turns text into vectors for similarity comparison.
model = SentenceTransformer("all-MiniLM-L6-v2")

# Example commands per category - used as reference points for similarity.
# Keys MUST match VALID_CATEGORIES in auditor.py exactly.
REFERENCE_EXAMPLES = {
    "http_disabled": ["no ip http server", "ip http server"],
    "remote_access": ["transport input ssh", "transport input telnet"],
    "pw_encryption": ["service password-encryption"],
    "enable_password": ["enable password", "enable secret"],
}

# Sanity check at import time - catch drift between the two files immediately
# rather than silently mismatching later.
assert set(REFERENCE_EXAMPLES.keys()) == set(VALID_CATEGORIES.keys()), (
    "REFERENCE_EXAMPLES categories are out of sync with auditor.VALID_CATEGORIES. "
    "Update this file to match."
)


def suggest_categories(unknown_line: str):
    """
    Compare the unknown line against all reference examples using MiniLM embeddings.
    Returns ALL categories, sorted by similarity, highest first.
    """
    unknown_embedding = model.encode(unknown_line, convert_to_tensor=True)

    scored = []
    for category, examples in REFERENCE_EXAMPLES.items():
        example_embeddings = model.encode(examples, convert_to_tensor=True)
        scores = util.cos_sim(unknown_embedding, example_embeddings)[0]
        best_idx = scores.argmax().item()
        scored.append((category, examples[best_idx], scores[best_idx].item()))

    scored.sort(key=lambda x: x[2], reverse=True)
    return scored


def train_unknown_with_suggestions(unknown_line: str):
    """
    HITL loop for a single unknown command line, using MiniLM-ranked suggestions
    instead of a static numbered menu.
    """
    print(f"\nUnknown:")
    print(f"{unknown_line}\n")

    suggestions = suggest_categories(unknown_line)

    print("Suggestions:")
    max_name_len = max(len(cat) for cat, _, _ in suggestions)
    for i, (category, example, score) in enumerate(suggestions, start=1):
        percentage = round(score * 100)
        print(f"{i}. {category.ljust(max_name_len)}   {percentage}%")
    print(f"{len(suggestions) + 1}. {'Ignore'.ljust(max_name_len)}   -")

    choice = input("\nChoose an option: ").strip()

    try:
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(suggestions):
            chosen_category = suggestions[choice_idx][0]
        else:
            print("\nCommand ignored.")
            return
    except ValueError:
        print("\nCommand ignored.")
        return

    # Save the FULL line as the key, not a short prefix - this matches
    # auditor.py's own train_unknown() behavior, and avoids a short/generic
    # prefix (like "no ip") accidentally matching unrelated future lines.
    ok, msg = train_command(unknown_line.strip(), chosen_category)
    print("\n" + (msg if ok else "Error: " + msg))


if __name__ == "__main__":
    # Quick standalone test - replace with a real unknown line from a config
    test_line = "no ip http server"
    train_unknown_with_suggestions(test_line)
