### Supabase CWE/CPE/CVE Data Extractor

## This is still in dev so I wouldn't add this to PROD just yet!
## The relationships data works to upload but since the supabase data is dependent on a foreign key, it won't upload to this specific instance

## Things needed:
1) CVE Data to be added to nodes tables (need to be discussed)
    - probably should hold off on doing this since it's going to add an additional 1M records
        - will probably slow down the searching on your end significantly for other searches because of time complexity searching row through row
        - this is mainly cause by the CPE table (has 1 Million rows because the amount of data is just huge)

2) CPE relationships should be talked about as well
    - the CPE specfic relationships are parent to child relationships
        - what I mean by this is that the initial CPE source node is technically the parent and the target nodes are just variations and versions of that specific endpoint
            - ex: the CPE parent is a macbook but the CPE child is the macbook x86 and arm so that's two different skus already but then if you also include other information, this can quickly spiral 
            - I HEAVILY RECOMMEND NOT ADDING THESE relationships (just use the parent relationship and you can search from there after since it's stored in the json data anyways)

3) Adding in the rest of the CWE data such as weaknesses, categories etc. since it will give more enriched information towards these CWEs and will require more tables to be created 

4) Adding in script to auto-create the CPE, CWE, and CVE tables through the supabase CLI

5) I think the original github is only taking in the archived data from CWE files and most likely should grab the recent - just realized this super late so will need to implement this to get the latest data rather than the older data
    - I actually downloaded all of the CWE files before but if you read them, it's all the same with slight changes to the data


## Things we can do to improve the tool later on
1) Concurrrency - what I mean by this is that we can have threads run multiple batches at the same time for extra speed but idk if this is necessary since this isn't business critical for speed (seems like once a day at most type of thing) 
    - if it's taking you more than 10 minutes for this whole tool, you are doing something wrong or you're running this on a potato/bad internet

2) currently it shows an error with unzipping the CPE files bc of reading an invalid filename but the script still runs and I wouldn't kill the script then


Ok let's talk about what each part does and what to expect from this:
# mainNodeDataInsert (will probably shorten that name later):
- This basically is where we are inserting the data and doing all of the batching and everything to help this tool work smoothly
- 3 different functions
    - query insertion
        - This portion is the brains of the entire script - it basically does the data processing in sequential order (CPE,CVE,CWE) and then the relationships since the relationships depend on the UUIDs that are generated from supabase
    - query data script
        - this handles inputting the data into supabase itself and will spit out + save the data locally so that the uuid can be referenced later on to be placed onto the relationships themselves
    - files to insert data
        - this handles the order at which the files will be ingested
- 
- we're basically working with 9 million rows from CPE data alone...
    - we definitely need to implement batching in order to have your computer not explode
    - this also helps so that instead of upserting at every processed line (9 million tasks!!!) we basically are doing 1000 at a time which isn't huge but helps a lot
- why we choose to upsert()
    - avoids duplicates and that data is updated which is nice bc it kills two birds w/ one stone 
        1) we're able to check for duplicates and avoid them to keep data clean
        2) update data everytime there is a new update or contributor to a CVE or CWE!!

# Data Extracts (CPE, CVE, CWE)
- This portion is basically reading the json files from the CPE, CVE, and CWE files that were downloaded through the scraper
    - It utilizes many for loops and separates the relationships logic from the node logic since we require the uuid from the nodes so it has to be done in sequential order
    - One difference with the CWE data is that it was originally XML so the formatting is a bit different, which is why the parsing/data extracts are different from the CPE and CVE data

# Scraper
- Finally, this portion is what's grabbing the data from the different sites hosting the CWE, CPE, and CVE data. There are quite a few functions going on in that script but the most important ones to call out are the batching and the CWE from xml to json transformations. The batching allows the script to take the unzipped files and split them up into smaller documents for processing and uploading to Supabase later on. For instance, the CPE files are around 1 GB big so it splits it up to 2000+ files.


How to run this script:
1) Update the .env file to match your credentials
2) Create the tables manually in supabase instance - use the enum_sql_queries to create them
3) run the main.js file after