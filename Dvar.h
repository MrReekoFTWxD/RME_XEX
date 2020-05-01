#pragma once


union DvarValue
{
	bool enabled;                               //0x01
	int integer;                                //0x04
	unsigned int unsignedInt;                   //0x04
	__int64 integer64;                          //0x08
	unsigned __int64 unsignedInt64;             //0x08
	float value;                                //0x04
	float vector[4];                            //0x10
	const char *string;                         //0x04
	char color[4];                              //0x04
}; //Size = 0x10

union DvarLimits
{
	struct
	{
		int stringCount;
		const char **strings;
	} enumeration;                              //0x08

	struct
	{
		int min;
		int max;
	} integer;                                  //0x08

	struct
	{
		__int64 min;
		__int64 max;
	} integer64;                                //0x10

	struct
	{
		float min;
		float max;
	} value, vector;                            //0x08
}; //Size = 0x10

struct dvar_s
{
	const char *name;                           //0x00
	const char *description;                    //0x04
	int hash;                                   //0x08
	unsigned int flags;                         //0x0C
	int type;                                   //0x10
	int modified;                               //0x14
	DvarValue current;                          //0x18
	DvarValue latched;                          //0x28
	DvarValue reset;                            //0x38
	DvarValue saved;                            //0x48
	DvarLimits domain;                          //0x58
	dvar_s *next;                               //0x68
}; //Size = 0x6C
