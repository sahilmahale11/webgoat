import pandas as pd
import json

# Load the JSON data from the file
with open('truffelhog_output.json', 'r') as json_file:
    data = json.load(json_file)

# Check the structure of the data and normalize it
# If the data is a list of dictionaries (common for scan reports), you can directly convert it
if isinstance(data, list):
    # Convert the JSON data to a pandas DataFrame
    df = pd.json_normalize(data)

    # Save the DataFrame to a CSV file
    df.to_csv('truffelhog_output.csv', index=False)
    print("Conversion completed! Check the truffelhog_output.csv file.")
else:
    print("Unexpected data structure. Please check the JSON file.")
