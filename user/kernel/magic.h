#define TUX3_MAGIC_SIZE 8
#define TUX3_MAGIC { 't', 'u', 'x', '3', 0xdd, 0x09, 0x03, 0x10 } /* date of latest incompatible sb format */
/*
 * disk format revision history
 * !!! always update this for every incompatible change !!!
 *
 * 2008-08-06: Beginning of time
 * 2008-09-06: Actual checking starts
 * 2008-12-12: Atom dictionary size in disksuper instead of atable->i_size
 * 2009-02-28: Attributes renumbered, rdev added
 * 2009-03-10: Alignment fix of disksuper
 */

