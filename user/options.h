#ifndef OPTIONS_H
#define OPTIONS_H

/*
 * Copyright (c) Daniel Phillips, 2002-2013
 * License for distribution granted under the terms of the GPL Version 3
 * The original author reserves the right to dual license this work
 * These lines must be preserved as is in any derivative of this work
 */

struct optv {
	unsigned size, argc, optc, err;
	const char *argv[];
};

struct options {
	const char *name, *terse;
	unsigned rule;
	const char *help, *arghelp, *defarg;
};

struct opt {
	int index;
	const char *value;
};

enum {
	OPT_NOARG,
	OPT_HASARG,
	OPT_OPTARG,

	OPT_NUMBER	= 4,
	OPT_MANY	= 8,
	OPT_MAX,

	OPT_ANYARG	= OPT_HASARG | OPT_OPTARG,
};

static inline struct opt *optentry(void *work, int i)
{
	struct optv *optv = work;
	return (struct opt *)((work + optv->size)) - i - 1;
}

static inline unsigned optindex(void *work, int i)
{
	return optentry(work, i)->index;
}

static inline const char *optvalue(void *work, int i)
{
	return optentry(work, i)->value;
}

static inline struct optv *argv2optv(const char *argv[])
{
	return (struct optv *)((char *)argv - offsetof(struct optv, argv));
}

int opthead(struct options *options, int *argc, const char ***argv, void *work, int size, int stop);
int optscan(struct options *options, int *argc, const char ***argv, void *work, int size);
int optspace(struct options *options, int argc, const char *argv[]);
int optcount(void *work, int opt);
const char *opterror(void *work);
int opthelp(void *buf, int bufsize, struct options *options, int tabs[3], char *lead, int brief);
const char *optbasename(const char *argv0);

#endif /* !OPTIONS_H */
