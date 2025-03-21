# Supabase CWE/CPE/CVE Data Extractor

> **Warning:** This tool is still in development. **Do not add this to production** yet!

Inspiration taken from: https://github.com/amberzovitis/GraphKer

---

## Overview

This tool is designed to extract and upload data related to CWE, CPE, and CVE into Supabase. It handles millions of records with efficient batching and relationship management between the datasets. Note that due to foreign key constraints, the CPE relationships might need special handling in your instance.

---

## Key Considerations
- The relationships data works to upload but since this supabase instance is dependent on a foreign key, it will run into errors here
- The reason why I haven't implmented the relationships data immediately is because of the sheer amount of nodes which will anundate the database (read below to see the data volume)

### Data Volume
- **CVE Data:**  
  - Adding CVE data to the nodes table could significantly increase the record count (by roughly 1M records).
  - This may slow down search operations because of the increased time complexity.

- **CPE Data:**  
  - The CPE specfic relationships are parent to child relationships
        - What I mean by this is that the initial CPE source node is technically the parent and the target nodes are just variations and versions of that specific endpoint
            - ex: the CPE parent is a macbook but the CPE child is the macbook x86 and arm so that's two different skus already but then if you also include other information, this can quickly spiral 
            - I HEAVILY RECOMMEND NOT ADDING THESE relationships (just use the parent relationship and you can search from there after since it's stored in the json data anyways)

- **CWE Data:**
  - Requires new tables for a more comprehensive dataset since we're currently just using the most recent file due to following the logic from the other repo.

### Data Relationships
- **CPE Relationships:**  
  - Represent parent-to-child relationships. For example, a "MacBook" (parent) might have child entries for different architectures (e.g., x86, ARM).
  - **Note:** It is highly recommended to avoid adding these child relationships explicitly. Instead, use the parent node and extract variations from the JSON data as needed.

### Future Improvements
1. **Concurrency:**  
   - Implement threading to process multiple batches simultaneously for increased speed.
   - This is not critical since the script runs at most once per day. If processing exceeds 10 minutes, recheck your setup or connection speed.

2. **Error Handling:**  
   - Currently, there is an error with unzipping the CPE files due to an invalid filename. The script continues to run despite this, so you may choose to ignore these errors.

---

## Script Breakdown

### Main Node Data Insert
This is the core component, responsible for:
- **Query Insertion:**  
  - Sequentially processes data from CPE, CVE, CWE and handles relationships using generated UUIDs from Supabase.
- **Query Data Script:**  
  - Inserts the data into Supabase and saves it locally for reference.
- **Files to Insert Data:**  
  - Manages the order in which files are ingested.

**Batching:**  
- Given that there are around 9 million rows from the CPE data alone, batching (e.g., 1000 records per batch) is implemented to avoid overwhelming your system.
- Uses `upsert()` to both avoid duplicates and update records, ensuring data integrity and freshness.

### Data Extraction
- **CPE, CVE, CWE Extraction:**  
  - Reads JSON files downloaded by the scraper.
  - Separates the extraction of relationships from the node logic (since relationships depend on UUIDs).
- **CWE Special Note:**  
  - Originally in XML format, hence requires different parsing and extraction logic.

### Scraper
- **Functionality:**  
  - Retrieves data from various sources hosting CWE, CPE, and CVE data.
  - Includes functions for batching and transforming CWE data from XML to JSON.
- **Batching:**  
  - The CPE file (around 1 GB) is split into 2000+ smaller files for processing and uploading.

---

## Setup Instructions

1. **Environment Configuration:**
   - Update the `.env` file with your Supabase credentials.

2. **Database Setup:**
   - You will need to manually create the required tables in your Supabase instance.
    - Please sse the provided sql queries in the `enum_sql_queries` file for table creation.
   - Add the required triggers for the CWE, CVE, and CPE tables in supabase to include the relationships data + nodes data

3. **Running the Script:**
   - Remember to compile w/ `tsc`
   - Execute the file using `node ./dist/main.js` to start the data extraction and insertion process.

4. **Including CPE relationships data**
   - If you would like to include the CPE relationships data, please go to `mainNodeDataInsert` as the instructions on where to uncomment will be there on lines 21-23.
    - Be sure to include `cperelationships` at the end of the array so that the process will be ran
   - *Warning*: The CPE child data is extremely large >20M rows and thus this will extend to both relationships + nodes tables as well

  

---

## Additional Notes

- **UUID Relationships:**  
  - Relationships depend on UUIDs generated by Supabase. Ensure sequential processing for these parts.
  
- **Error Handling:**  
  - Unzipping errors for CPE files due to invalid filenames are known issues. The script continues running despite these errors.

- **Future Enhancements:**  
  - Consider adding concurrency for faster batch processing.
  - Review and potentially refine error handling and logging for better troubleshooting.
  - Using supabase CLI to auto create the tables within instance
    - creating more supabase functions to handle the data insertion and uuid conflicts
  - Adding in the rest of the CWE data such as weaknesses, categories etc. since it will give more enriched information towards these CWEs and will require more tables to be created 

