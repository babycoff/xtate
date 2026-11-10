
#ifndef NOT_FOUND_BSON
#ifndef BSON_OUTPUT_H
#define BSON_OUTPUT_H

/**
 * Parse BSON result file to JSON format and output to stdout.
 * @param filename file name of BSON file
 * @param is_pretty print readable JSON format result
 */
int parse_bson_file(const char *filename);

#endif
#endif