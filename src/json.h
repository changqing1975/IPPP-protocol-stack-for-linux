#ifndef JSON__h
#define JSON__h

/* json Types: */
#define JSON__False 0
#define JSON__True 1
#define JSON__NULL 2
#define JSON__Number 3
#define JSON__String 4
#define JSON__Array 5
#define JSON__Object 6
	
#define JSON__IsReference 256
#define JSON__StringIsConst 512

/* The json structure: */
typedef struct json {
	struct json *next,*prev;	/* next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem */
	struct json *child;		/* An array or object item will have a child pointer pointing to a chain of the items in the array/object. */

	int type;					/* The type of the item, as above. */

	char *valuestring;			/* The item's string, if type==JSON__String */
	int valueint;				/* The item's number, if type==JSON__Number */
	double valuedouble;			/* The item's number, if type==JSON__Number */

	char *string;				/* The item's name string, if this item is the child of, or is in the list of subitems of an object. */
} json;

/* Supply a block of JSON, and this returns a json object you can interrogate. Call JSON__Delete when finished. */
extern json *JSON__Parse(const char *value);

/* Delete a json entity and all subentities. */
extern void   JSON__Delete(json *c);

/* Returns the number of items in an array (or object). */
extern int	  JSON__GetArraySize(json *array);
/* Retrieve item number "item" from array "array". Returns NULL if unsuccessful. */
extern json *JSON__GetArrayItem(json *array,int item);
/* Get item "string" from object. Case insensitive. */
extern json *JSON__GetObjectItem(json *object,const char *string);

/* ParseWithOpts allows you to require (and check) that the JSON is null terminated, and to retrieve the pointer to the final byte parsed. */
extern json *JSON__ParseWithOpts(const char *value,const char **return_parse_end,int require_null_terminated);

#endif