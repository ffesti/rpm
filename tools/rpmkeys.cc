#include "system.h"

#include <popt.h>
#include <rpm/rpmcli.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmkeyring.h>
#include <rpm/rpmlog.h>
#include "cliutils.hh"
#include "debug.h"

enum modes {
    MODE_CHECKSIG	= (1 << 0),
    MODE_IMPORTKEY	= (1 << 1),
    MODE_DELKEY		= (1 << 2),
    MODE_LISTKEY	= (1 << 3),
};

static int mode = 0;
static int test = 0;

static struct poptOption keyOptsTable[] = {
    { "checksig", 'K', (POPT_ARG_VAL|POPT_ARGFLAG_OR), &mode, MODE_CHECKSIG,
	N_("verify package signature(s)"), NULL },
    { "import", '\0', (POPT_ARG_VAL|POPT_ARGFLAG_OR), &mode, MODE_IMPORTKEY,
	N_("import an armored public key"), NULL },
    { "test", '\0', POPT_ARG_NONE, &test, 0,
	N_("don't import, but tell if it would work or not"), NULL },
    { "delete", '\0', (POPT_ARG_VAL|POPT_ARGFLAG_OR), &mode, MODE_DELKEY,
	N_("delete keys from RPM keyring"), NULL },
    { "list", '\0', (POPT_ARG_VAL|POPT_ARGFLAG_OR), &mode, MODE_LISTKEY,
	N_("list keys from RPM keyring"), NULL },
    POPT_TABLEEND
};

static struct poptOption optionsTable[] = {
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, keyOptsTable, 0,
	N_("Keyring options:"), NULL },
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, rpmcliAllPoptTable, 0,
	N_("Common options for all rpm modes and executables:"), NULL },

    POPT_AUTOALIAS
    POPT_AUTOHELP
    POPT_TABLEEND
};

static ARGV_t gpgkeyargs(ARGV_const_t args) {
    ARGV_t gpgargs = NULL;
    for (char * const * arg = args; *arg; arg++) {
	if (strncmp(*arg, "gpg-pubkey-", 11)) {
	    char * gpgarg = NULL;
	    rstrscat(&gpgarg, "gpg-pubkey-", *arg, NULL);
	    argvAdd(&gpgargs, gpgarg);
	    free(gpgarg);
	} else {
	    argvAdd(&gpgargs, *arg);
	}
    }
    return gpgargs;
}

static int matchingKeys(rpmKeyring keyring, ARGV_const_t args, void * userdata, int callback(rpmPubkey, void*))
{
    int ec = EXIT_SUCCESS;
    if (args) {
	for (char * const * arg = args; *arg; arg++) {
	    int found = false;
	    auto iter = rpmKeyringGetIterator(keyring);
	    rpmPubkey key = rpmKeyringIteratorNext(iter);
	    while (key) {
		char * fp = rpmPubkeyFingerprintAsHex(key);
		char * keyid = rpmPubkeyKeyIDAsHex(key);
		if (!strcmp(*arg, fp) || !strcmp(*arg, keyid)) {
		    found = true;
		}
		free(fp);
		free(keyid);
		if (found)
		    break;
		rpmPubkeyFree(key);
		key = rpmKeyringIteratorNext(iter);
	    }
	    rpmKeyringIteratorFree(iter);
	    if (found) {
		callback(key, userdata);
		rpmPubkeyFree(key);
	    } else {
		rpmlog(RPMLOG_NOTICE, "Key %s not found\n", *arg);
		ec = EXIT_FAILURE;
	    }
	}
    } else {
	int found = false;
	auto iter = rpmKeyringGetIterator(keyring);
	rpmPubkey key = rpmKeyringIteratorNext(iter);
	while (key) {
	    found = true;
	    callback(key, userdata);
	    rpmPubkeyFree(key);
	    key = rpmKeyringIteratorNext(iter);
	}
	rpmKeyringIteratorFree(iter);
	if (!found) {
	    rpmlog(RPMLOG_NOTICE, "No keys installed\n");
	    ec = EXIT_FAILURE;
	}
    }
    return ec;
}

static int printKey(rpmPubkey key, void * data)
{
    char * fp = rpmPubkeyFingerprintAsHex(key);
    pgpDigParams params = rpmPubkeyPgpDigParams(key);
    rpmlog(RPMLOG_NOTICE, "%s %s public key\n", fp, pgpDigParamsUserID(params));
    free(fp);
    return 0;
}

static int printKeyLong(rpmPubkey key, void * data)
{
    char * fp = rpmPubkeyFingerprintAsHex(key);
    char * keyid = rpmPubkeyKeyIDAsHex(key);
    pgpDigParams params = rpmPubkeyPgpDigParams(key);
    const time_t unixtime = pgpDigParamsCreationTime(params);
    rpmlog(RPMLOG_NOTICE, "Public key\n");
    rpmlog(RPMLOG_NOTICE, "Issuer:         %s\n", pgpDigParamsUserID(params));
    rpmlog(RPMLOG_NOTICE, "Fingerprint:    %s\n", fp);
    rpmlog(RPMLOG_NOTICE, "Key ID:         %s\n", keyid);
    rpmlog(RPMLOG_NOTICE, "Creation Time:  %s", asctime(gmtime(&unixtime)));
    rpmlog(RPMLOG_NOTICE, "Version:        V%i\n", pgpDigParamsVersion(params));
    rpmlog(RPMLOG_NOTICE, "Key algorithm:  %s\n", pgpValString(PGPVAL_PUBKEYALGO, pgpDigParamsAlgo(params, PGPVAL_PUBKEYALGO)));
    
    rpmlog(RPMLOG_NOTICE, "Hash algorithm: %s\n", pgpValString(PGPVAL_HASHALGO, pgpDigParamsAlgo(params, PGPVAL_HASHALGO)));
    rpmlog(RPMLOG_NOTICE, "\n");
    free(fp);
    free(keyid);
    return 0;

}

int main(int argc, char *argv[])
{
    int ec = EXIT_FAILURE;
    poptContext optCon = NULL;
    rpmts ts = NULL;
    ARGV_const_t args = NULL;
    rpmKeyring keyring = NULL;

    optCon = rpmcliInit(argc, argv, optionsTable);

    if (argc < 2) {
	printUsage(optCon, stderr, 0);
	goto exit;
    }

    args = (ARGV_const_t) poptGetArgs(optCon);

    if (mode != MODE_LISTKEY && args == NULL)
	argerror(_("no arguments given"));

    ts = rpmtsCreate();
    rpmtsSetRootDir(ts, rpmcliRootDir);
    keyring = rpmtsGetKeyring(ts, 1);

    switch (mode) {
    case MODE_CHECKSIG:
	ec = rpmcliVerifySignatures(ts, args);
	break;
    case MODE_IMPORTKEY:
	if (test)
	    rpmtsSetFlags(ts, (rpmtsFlags(ts)|RPMTRANS_FLAG_TEST));
	ec = rpmcliImportPubkeys(ts, args);
	break;
    case MODE_DELKEY:
    {
	struct rpmInstallArguments_s * ia = &rpmIArgs;
	ARGV_t gpgargs = gpgkeyargs(args);
	ec = rpmErase(ts, ia, gpgargs);
	argvFree(gpgargs);
	break;
    }
    case MODE_LISTKEY:
    {
	if (rpmIsVerbose())
	    ec = matchingKeys(keyring, args, NULL, printKeyLong);
	else
	    ec = matchingKeys(keyring, args, NULL, printKey);
	break;
    }
    default:
	argerror(_("only one major mode may be specified"));
    }

exit:
    rpmKeyringFree(keyring);
    rpmtsFree(ts);
    rpmcliFini(optCon);
    fflush(stderr);
    fflush(stdout);
    if (ferror(stdout) || ferror(stderr))
	return 255; /* I/O error */
    return ec;
}
