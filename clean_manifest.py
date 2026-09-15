import csv

MANIFEST_PATH = r"E:\SIH_2026\manifest.csv"

# Read all rows, keeping only the LAST occurrence of each filename
rows_by_filename = {}
header = None

with open(MANIFEST_PATH, newline="") as f:
    reader = csv.reader(f)
    header = next(reader)
    for row in reader:
        filename = row[0]
        rows_by_filename[filename] = row  # later rows overwrite earlier ones

print(f"Unique filenames after dedup: {len(rows_by_filename)}")

with open(MANIFEST_PATH, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(rows_by_filename.values())

print("Manifest cleaned and saved.")