
from security_monitor import inspect_input


# Label each sample according to its intended purpose.
# True = suspicious; False = harmless.
SAMPLES = [
    ("Script tag", "<script>alert('test')</script>", True),
    ("Event handler", '<img onerror="test">', True),
    ("JavaScript scheme", "javascript:example", True),
    ("Plain text", "Hello, how are you?", False),
    ("HTML documentation", "Use <b>bold</b> to emphasize a word.", False),
    ("JavaScript discussion", "I am learning JavaScript programming.", False),
    ("Encoded example", "&lt;script&gt;alert(1)&lt;/script&gt;", False),
    ("Comparison", "The score is greater than 50 > 40.", False),
    ("HTML documentation with attributes",'Example: <a href="guide">read the guide</a>.',False,),
    ("HTML with event handler",'<img src="x" onerror="test">', True,),
]


def main():
    true_positives = 0
    false_blocks = 0
    false_reviews = 0
    true_negatives = 0
    false_negatives = 0
    flagged_for_review = 0
    harmless_count = sum(not sample[2] for sample in SAMPLES)
    suspicious_count = sum(sample[2] for sample in SAMPLES)

    print(f"{'Sample':<34} {'Label':<12} {'Action':<8} Result")
    print("-" * 80)

    for name, payload, suspicious in SAMPLES:
        result = inspect_input(payload)
        action = result["action"]

        if action == "FLAG":
            flagged_for_review += 1

        if suspicious:
            if action in ("BLOCK", "FLAG"):
                true_positives += 1
                status = "Detected"
            else:
                false_negatives += 1
                status = "Missed suspicious input"
        else:
            if action == "BLOCK":
                false_blocks += 1
                status = "False block"
            elif action == "FLAG":
                false_reviews += 1
                status = "False review"
            else:
                true_negatives += 1
                status = "Correct acceptance"

        label = "Suspicious" if suspicious else "Harmless"
        print(f"{name:<34} {label:<12} {action:<8} {status}")

    false_block_rate = (
        false_blocks / harmless_count * 100 if harmless_count else 0
    )
    false_review_rate = (
        false_reviews / harmless_count * 100 if harmless_count else 0
    )
    miss_rate = (
        false_negatives / suspicious_count * 100
        if suspicious_count else 0
    )

    print("\n--- Evaluation Summary ---")
    print(f"Total samples: {len(SAMPLES)}")
    print(f"Suspicious samples detected: {true_positives}")
    print(f"Harmless inputs correctly accepted: {true_negatives}")
    print(f"False blocks: {false_blocks}")
    print(f"False reviews: {false_reviews}")
    print(f"Missed suspicious inputs: {false_negatives}")
    print(f"Inputs flagged for review: {flagged_for_review}")
    print(f"False-block rate: {false_block_rate:.1f}%")
    print(f"False-review rate: {false_review_rate:.1f}%")
    print(f"Suspicious-input miss rate: {miss_rate:.1f}%")


if __name__ == "__main__":
    main()
