#!/usr/bin/env python3
import sys
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='/opt/splunk/var/log/splunk/nodeheim_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s'
)

def main():
    try:
        logging.debug("Script starting at: %s", datetime.now())

        # Import Splunk libraries
        import splunk.Intersplunk
        logging.debug("Successfully imported splunk.Intersplunk")

        # Get the keywords and options from Splunk
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
        logging.debug(f"Keywords: {keywords}, Options: {options}")

        # Get any results that were passed in
        results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
        logging.debug(f"Got {len(results)} results from input")

        # Test event generation
        test_event = {
            'source': 'nodeheim:scan',
            'sourcetype': 'nodeheim:scan',
            '_time': datetime.now().timestamp(),
            'host': 'test_host',
            'status': 'test_successful',
            'keywords': str(keywords),
            'options': str(options)
        }

        # Output the results
        splunk.Intersplunk.outputResults([test_event])
        logging.debug("Successfully output test event")

    except Exception as e:
        logging.error("Fatal error: %s", str(e))
        import traceback
        logging.error("Traceback: %s", traceback.format_exc())
        splunk.Intersplunk.generateErrorResults(str(e))
    finally:
        logging.debug("Script completed at: %s", datetime.now())

if __name__ == "__main__":
    main()