#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/math.h>
#include <linux/limits.h>
#include <linux/ctype.h>
#include "json.h"

static const char *ep;

static int JSON__strcasecmp(const char *s1,const char *s2) {
	if (!s1)
		return (s1==s2)?0:1;
	if (!s2)
		return 1;
	for(; tolower(*s1) == tolower(*s2); ++s1, ++s2)	if(*s1 == 0)	return 0;
	return tolower(*(const unsigned char *)s1) - tolower(*(const unsigned char *)s2);
}

/* Internal constructor. */
static json *JSON__New_Item(void) {
	json* node = (json*)kmalloc(sizeof(json), GFP_KERNEL);
	if (node) memset(node,0,sizeof(json));
	return node;
}

/* Delete a json structure. */
void JSON__Delete(json *c) {
	json *next;
	while (c)
	{
		next=c->next;
		if (!(c->type&JSON__IsReference) && c->child) JSON__Delete(c->child);
		if (!(c->type&JSON__IsReference) && c->valuestring) kfree(c->valuestring);
		if (!(c->type&JSON__StringIsConst) && c->string) kfree(c->string);
		kfree(c);
		c=next;
	}
}

/* Parse the input text to generate a number, and populate the result into item. */
static const char *parse_number(json *item,const char *num) {
	long int n=0;

	// if (*num=='-') sign=-1,num++;	/* Has sign? */
	if (*num>='0' && *num<='9')
	{
		do{
			n=(n*10)+(*num++ -'0');
		}while (*num>='0' && *num<='9');	/* Number? */
	}

	// item->valuedouble=n;
	item->valueint=(int)n;
	item->type=JSON__Number;
	return num;
}

static unsigned parse_hex4(const char *str) {
	unsigned h=0;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	h=h<<4;str++;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	h=h<<4;str++;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	h=h<<4;str++;
	if (*str>='0' && *str<='9') h+=(*str)-'0'; else if (*str>='A' && *str<='F') h+=10+(*str)-'A'; else if (*str>='a' && *str<='f') h+=10+(*str)-'a'; else return 0;
	return h;
}

/* Parse the input text into an unescaped cstring, and populate item. */
static const unsigned char firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static const char *parse_string(json *item,const char *str) {
	const char *ptr=str+1;char *ptr2;char *out;int len=0;unsigned uc,uc2;
	if (*str!='\"') {ep=str;return 0;}	/* not a string! */
	
	while (*ptr!='\"' && *ptr && ++len) if (*ptr++ == '\\') ptr++;	/* Skip escaped quotes. */
	
	out=(char*)kmalloc(len+1, GFP_KERNEL);	/* This is how long we need for the string, roughly. */
	if (!out) return 0;
	
	ptr=str+1;ptr2=out;
	while (*ptr!='\"' && *ptr)
	{
		if (*ptr!='\\') *ptr2++=*ptr++;
		else
		{
			ptr++;
			switch (*ptr)
			{
				case 'b': *ptr2++='\b';	break;
				case 'f': *ptr2++='\f';	break;
				case 'n': *ptr2++='\n';	break;
				case 'r': *ptr2++='\r';	break;
				case 't': *ptr2++='\t';	break;
				case 'u':	 /* transcode utf16 to utf8. */
					uc=parse_hex4(ptr+1);ptr+=4;	/* get the unicode char. */

					if ((uc>=0xDC00 && uc<=0xDFFF) || uc==0)	break;	/* check for invalid.	*/

					if (uc>=0xD800 && uc<=0xDBFF)	/* UTF16 surrogate pairs.	*/
					{
						if (ptr[1]!='\\' || ptr[2]!='u')	break;	/* missing second-half of surrogate.	*/
						uc2=parse_hex4(ptr+3);ptr+=6;
						if (uc2<0xDC00 || uc2>0xDFFF)		break;	/* invalid second-half of surrogate.	*/
						uc=0x10000 + (((uc&0x3FF)<<10) | (uc2&0x3FF));
					}

					len=4;if (uc<0x80) len=1;else if (uc<0x800) len=2;else if (uc<0x10000) len=3; ptr2+=len;
					
					switch (len) {
						case 4:
							*--ptr2 =((uc | 0x80) & 0xBF);
							uc >>= 6;
							break;
						case 3:
							*--ptr2 =((uc | 0x80) & 0xBF);
							uc >>= 6;
							break;
						case 2:
							*--ptr2 =((uc | 0x80) & 0xBF);
							uc >>= 6;
							break;
						case 1:
							*--ptr2 =(uc | firstByteMark[len]);
					}
					ptr2+=len;
					break;
				default:  *ptr2++=*ptr; break;
			}
			ptr++;
		}
	}
	*ptr2=0;
	if (*ptr=='\"') ptr++;
	item->valuestring=out;
	item->type=JSON__String;
	return ptr;
}

/* Predeclare these prototypes. */
static const char *parse_value(json *item,const char *value);
// static char *print_value(json *item,int depth,int fmt,printbuffer *p);
static const char *parse_array(json *item,const char *value);
// static char *print_array(json *item,int depth,int fmt,printbuffer *p);
static const char *parse_object(json *item,const char *value);
// static char *print_object(json *item,int depth,int fmt,printbuffer *p);

/* Utility to jump whitespace and cr/lf */
static const char *skip(const char *in) {while (in && *in && (unsigned char)*in<=32) in++; return in;}

/* Parse an object - create a new root, and populate. */
json *JSON__ParseWithOpts(const char *value,const char **return_parse_end,int require_null_terminated) {
	const char *end=0;
	json *c=JSON__New_Item();
	ep=0;
	if (!c) return 0;       /* memory fail */

	end=parse_value(c,skip(value));
	if (!end)	{JSON__Delete(c);return 0;}	/* parse failure. ep is set. */

	/* if we require null-terminated JSON without appended garbage, skip and then check for a null terminator */
	if (require_null_terminated) {end=skip(end);if (*end) {JSON__Delete(c);ep=end;return 0;}}
	if (return_parse_end) *return_parse_end=end;
	return c;
}
/* Default options for JSON__Parse */
json *JSON__Parse(const char *value) {return JSON__ParseWithOpts(value,0,0);}

/* Parser core - when encountering text, process appropriately. */
static const char *parse_value(json *item,const char *value) {
	if (!value)						return 0;	/* Fail on null. */
	if (!strncmp(value,"null",4))	{ item->type=JSON__NULL;  return value+4; }
	if (!strncmp(value,"false",5))	{ item->type=JSON__False; return value+5; }
	if (!strncmp(value,"true",4))	{ item->type=JSON__True; item->valueint=1;	return value+4; }
	if (*value=='\"')				{ return parse_string(item,value); }
	if (*value=='-' || (*value>='0' && *value<='9'))	{ return parse_number(item,value); }
	if (*value=='[')				{ return parse_array(item,value); }
	if (*value=='{')				{ return parse_object(item,value); }

	ep=value;return 0;	/* failure. */
}

/* Build an array from input text. */
static const char *parse_array(json *item,const char *value) {
	json *child;
	if (*value!='[')	{ep=value;return 0;}	/* not an array! */

	item->type=JSON__Array;
	value=skip(value+1);
	if (*value==']') return value+1;	/* empty array. */

	item->child=child=JSON__New_Item();
	if (!item->child) return 0;		 /* memory fail */
	value=skip(parse_value(child,skip(value)));	/* skip any spacing, get the value. */
	if (!value) return 0;

	while (*value==',')
	{
		json *new_item;
		if (!(new_item=JSON__New_Item())) return 0; 	/* memory fail */
		child->next=new_item;new_item->prev=child;child=new_item;
		value=skip(parse_value(child,skip(value+1)));
		if (!value) return 0;	/* memory fail */
	}

	if (*value==']') return value+1;	/* end of array */
	ep=value;return 0;	/* malformed. */
}

/* Build an object from the text. */
static const char *parse_object(json *item,const char *value) {
	json *child;
	if (*value!='{')	{ep=value;return 0;}	/* not an object! */
	
	item->type=JSON__Object;
	value=skip(value+1);
	if (*value=='}') return value+1;	/* empty array. */
	
	item->child=child=JSON__New_Item();
	if (!item->child) return 0;
	value=skip(parse_string(child,skip(value)));
	if (!value) return 0;
	child->string=child->valuestring;child->valuestring=0;
	if (*value!=':') {ep=value;return 0;}	/* fail! */
	value=skip(parse_value(child,skip(value+1)));	/* skip any spacing, get the value. */
	if (!value) return 0;
	
	while (*value==',')
	{
		json *new_item;
		if (!(new_item=JSON__New_Item()))	return 0; /* memory fail */
		child->next=new_item;new_item->prev=child;child=new_item;
		value=skip(parse_string(child,skip(value+1)));
		if (!value) return 0;
		child->string=child->valuestring;child->valuestring=0;
		if (*value!=':') {ep=value;return 0;}	/* fail! */
		value=skip(parse_value(child,skip(value+1)));	/* skip any spacing, get the value. */
		if (!value) return 0;
	}
	
	if (*value=='}') return value+1;	/* end of array */
	ep=value;return 0;	/* malformed. */
}

/* Get Array size/item / object item. */
int   JSON__GetArraySize(json *array)						{json *c=array->child;int i=0;while(c)i++,c=c->next;return i;}
json *JSON__GetArrayItem(json *array,int item)				{json *c=array->child;  while (c && item>0) item--,c=c->next; return c;}
json *JSON__GetObjectItem(json *object,const char *string)	{json *c=object->child; while (c && JSON__strcasecmp(c->string,string)) c=c->next; return c;}
