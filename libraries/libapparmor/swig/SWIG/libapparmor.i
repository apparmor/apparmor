%module LibAppArmor

%{
#include <aalogparse.h>
#include <sys/apparmor.h>
#include <sys/apparmor_private.h>

// Include static_assert if the C compiler supports it
// static_assert standardized since C11, assert.h not needed since C23
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && __STDC_VERSION__ < 202311L
#include <assert.h>
#endif
%}

%include "typemaps.i"
%include <cstring.i>
%include <stdint.i>
%include <exception.i>

/*
 * SWIG 4.3 included https://github.com/swig/swig/pull/2907 to distinguish
 * between Py_None being returned as a default void and Py_None being returned
 * as the equivalent of C NULL. Unfortunately, this turns into an API breaking
 * change with our use of %append_output when we want the Python function to
 * return something even when the C function has a void return type. Thus, we
 * need an additional macro to smooth over the differences. Include all affected
 * languages, even ones we don't build bindings for, for completeness.
 */
#if SWIG_VERSION >= 0x040300
#ifdef SWIGPYTHON
#define ISVOID_APPEND_OUTPUT(value) {$result = SWIG_Python_AppendOutput($result, value, 1);}
#elif defined(SWIGRUBY)
#define ISVOID_APPEND_OUTPUT(value) {$result = SWIG_Ruby_AppendOutput($result, value, 1);}
#elif defined(SWIGPHP)
#define ISVOID_APPEND_OUTPUT(value) {$result = SWIG_Php_AppendOutput($result, value, 1);}
#else
#define ISVOID_APPEND_OUTPUT(value) %append_output(value)
#endif
#else
#define ISVOID_APPEND_OUTPUT(value) %append_output(value)
#endif

%newobject parse_record;
%delobject free_record;
/*
 * Despite its name, %delobject does not hook up destructors to language
 * deletion mechanisms. Instead, it sets flags so that manually calling the
 * free function and then deleting by language mechanisms doesn't cause a
 * double-free.
 *
 * Additionally, we can manually extend the struct with a C++-like
 * destructor. This ensures that the record struct is freed 
 * automatically when the high-level object goes out of scope.
 */
%extend aa_log_record {
	~aa_log_record() {
		free_record($self);
	}
}

/*
 * Generate a no-op free_record wrapper to avoid making a double-free footgun.
 * Use rename directive to avoid colliding with the actual free_record, which
 * we use above to clean up when the higher-level language deletes the object.
 * 
 * Ideally we would not expose a free_record at all, but we need to maintain
 * backwards compatibility with the existing high-level code that uses it.
 */
%rename(free_record) noop_free_record;
#ifdef SWIGPYTHON
%pythonprepend noop_free_record %{
import warnings
warnings.warn("free_record is now a no-op as the record's memory is handled automatically", DeprecationWarning)
%}
#endif
%feature("autodoc",
  "This function used to free aa_log_record objects. Freeing is now handled "
  "automatically, so this no-op function remains for backwards compatibility.") noop_free_record;
%inline %{
  void noop_free_record(aa_log_record *record) {(void) record;}
%}

/*
 * Do not autogenerate a wrapper around free_record. This does not prevent us
 * from calling it ourselves in %extend C code.
 */
%ignore free_record;


/*
 * Map names to preserve backwards compatibility
 */
#ifdef SWIGPYTHON
%rename("_class") aa_log_record::rule_class;
#else
%rename("class") aa_log_record::rule_class;
#endif
%rename("namespace") aa_log_record::aa_namespace;

%include <aalogparse.h>

/**
 * swig doesn't like the macro magic we do in apparmor.h and apparmor_private.h
 * so the function prototypes must be manually inserted.
 *
 * Functions that return a negative int and set errno upon error use a special
 * %exception directive and must be listed after the %exception below. All
 * other functions go here.
 */

/* apparmor.h */

/*
 * label is a heap-allocated pointer, but when label and mode occur together,
 * the freeing of label must be deferred because mode points into label.
 *
 * %cstring_output_allocate((char **label, char **mode), free(*$1))
 * does not handle multi-argument typemaps correctly, so we write our own
 * typemap based on it instead.
 */
%typemap(in,noblock=1,numinputs=0) (char **label, char **mode) ($*1_ltype temp_label = 0, $*2_ltype temp_mode = 0) {
  $1 = &temp_label;
  $2 = &temp_mode;
}
%typemap(freearg,match="in") (char **label, char **mode) ""
%typemap(argout,noblock=1,fragment="SWIG_FromCharPtr") (char **label, char **mode) {
  ISVOID_APPEND_OUTPUT(SWIG_FromCharPtr(*$1));
  ISVOID_APPEND_OUTPUT(SWIG_FromCharPtr(*$2));
  free(*$1);
}

/*
 * mode also occurs in combination with con in aa_splitcon
 * typemap based on %cstring_mutable but with substantial modifications
 */
%typemap(in,numinputs=1,fragment="SWIG_AsCharPtrAndSize") (char *con, char **mode) ($*2_ltype temp_mode = 0) {
  int alloc_status = 0;
  $1_ltype con_ptr = NULL;
  size_t con_len = 0;
  int char_ptr_res = SWIG_AsCharPtrAndSize($input, &con_ptr, &con_len, &alloc_status);
  if (!SWIG_IsOK(char_ptr_res)) {
    %argument_fail(char_ptr_res, "char *con", $symname, $argnum);
  }
  if (alloc_status != SWIG_NEWOBJ) {
    // Unconditionally copy because the C function modifies the string in place
    $1 = %new_array(con_len+1, char);
    if ($1 == NULL) {
      SWIG_exception_fail(SWIG_MemoryError, "could not allocate C con_ptr copy array");
    }
    memcpy($1, con_ptr, con_len+1);
  } else {
    $1 = con_ptr;
  }

  $2 = &temp_mode;
}
%typemap(freearg,noblock=1,match="in") (char *con, char **mode) {
  %delete_array($1);
}
%typemap(argout,noblock=1,fragment="SWIG_FromCharPtr") (char *con, char **mode) {
  /*
   * aa_splitcon returns either con or NULL so we don't need to explicitly
   * append it to the output, and we don't need the ISVOID helper here
   * 
   * SWIG_FromCharPtr does NULL checks for us
   */
  %append_output(SWIG_FromCharPtr(*$2));
}

%exception aa_splitcon {
  $action
  if (result == NULL) {
    SWIG_exception_fail(SWIG_ValueError, "received invalid confinement context");
  }
}

extern char *aa_splitcon(char *con, char **mode);

#ifdef SWIGPYTHON
%exception {
  $action
  if (result < 0) {
    // Unfortunately SWIG_exception does not support OSError
    PyErr_SetFromErrno(PyExc_OSError);
    SWIG_fail;
  }
}
#endif

/* Functions that return a negative int and set errno upon error go here. */

/* apparmor.h */

/*
 * aa_is_enabled returns a boolean as an int with failure reason in errno 
 * Therefore, aa_is_enabled either returns True or throws an exception
 *
 * Keep that behavior for backwards compatibilty but return a boolean on Python
 * where it makes more sense, which isn't a breaking change because a boolean is
 * a subclass of int
 */
#ifdef SWIGPYTHON
%typemap(out) int {
	$result = PyBool_FromLong($1);
}
#endif
extern int aa_is_enabled(void);

#ifdef SWIGPYTHON
// Based on SWIG's argcargv.i but we don't have an argc
%typemap(in,fragment="SWIG_AsCharPtr") const char *subprofiles[] (Py_ssize_t seq_len=0, int* alloc_tracking = NULL) {
  void* arg_as_ptr = NULL;
  int res_convertptr = SWIG_ConvertPtr($input, &arg_as_ptr, $descriptor(char*[]), 0);
  if (SWIG_IsOK(res_convertptr)) {
    $1 = %static_cast(arg_as_ptr, $1_ltype);
  } else {
    // Clear error that would be set if ptr conversion failed
    PyErr_Clear();

    int is_list = PyList_Check($input);
    if (is_list || PyTuple_Check($input)) {
      seq_len = PySequence_Length($input);
      /*
       * %new_array zero-inits for cleaner error handling and memory cleanup
       * %delete_array(NULL) is no-op (either free or delete), and
       * alloc_tracking of 0 is uninit
       * 
       * Further note: SWIG_exception_fail jumps to the freearg typemap
       */
      $1 = %new_array(seq_len+1, char *);
      if ($1 == NULL) {
        SWIG_exception_fail(SWIG_MemoryError, "could not allocate C subprofiles");
      }

      alloc_tracking = %new_array(seq_len, int);
      if (alloc_tracking == NULL) {
        SWIG_exception_fail(SWIG_MemoryError, "could not allocate C alloc track arr");
      }
      for (Py_ssize_t i=0; i<seq_len; i++) {
        PyObject *o = is_list ? PyList_GetItem($input, i) : PyTuple_GetItem($input, i);
        if (o == NULL) {
          // Failed to get item-Python already set exception info
          SWIG_fail;
        } else if (o == Py_None) {
          // SWIG_AsCharPtr(Py_None, ...) succeeds with ptr output being NULL
          SWIG_exception_fail(SWIG_ValueError, "sequence contains a None object");
        }
        int res = SWIG_AsCharPtr(o, &$1[i], &alloc_tracking[i]);
        if (!SWIG_IsOK(res)) {
          // Could emit idx of error here, maybe?
          SWIG_exception_fail(SWIG_ArgError(res), "sequence does not contain all strings");
        }
      }
    } else {
      SWIG_exception_fail(SWIG_TypeError, "subprofiles is not a list or tuple");
    }
  }
}
%typemap(freearg,noblock=1) const char *subprofiles[] {
/*
 * If static_assert is present, use it to verify the assumption that
 * allocation uninitialized (0) != SWIG_NEWOBJ
 */
%#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  /* 
   * Some older versions of SWIG place this right after a goto label
   * This would then be a label followed by a declaration, a C23 extension (!)
   * To ensure this works for older SWIG versions and older compilers,
   * make this a block element with curly braces.
   */
  {static_assert(SWIG_NEWOBJ != 0, "SWIG_NEWOBJ is 0");}
%#endif
  if ($1 != NULL && alloc_tracking$argnum != NULL) {
    for (Py_ssize_t i=0; i<seq_len$argnum; i++) {
      if (alloc_tracking$argnum[i] == SWIG_NEWOBJ) {
        %delete_array($1[i]);
      }
    }
  }
  %delete_array(alloc_tracking$argnum);
  %delete_array($1);
}
#endif

#ifdef SWIGPERL
// Copied from perl's argcargv.i, which should be good enough for us
%typemap(in) (const char *subprofiles[]) {
  int i;
  SSize_t len;
  AV *av = (AV *)SvRV($input);
  if (SvTYPE(av) != SVt_PVAV) {
    SWIG_croak("in method '$symname', Expecting reference to argv array");
    goto fail;
  }
  len = av_len(av) + 1;
  $1 = (char **) malloc((len+1)*sizeof(char *));
  for (i = 0; i < len; i++) {
    SV **tv = av_fetch(av, i, 0);
    $1[i] = SvPV_nolen(*tv);
  }
  $1[i] = NULL;
}

%typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) (const char *subprofiles[]) {
  AV *av = (AV *)SvRV($input);
  $1 = SvTYPE(av) == SVt_PVAV;
}

%typemap(freearg) (const char *subprofiles[]) {
  free((void *)$1);
}
#endif

/* These should not receive the VOID_Object typemap */
extern int aa_change_hat(const char *subprofile, unsigned long magic_token);
extern int aa_change_profile(const char *profile);
extern int aa_change_onexec(const char *profile);
extern int aa_change_hatv(const char *subprofiles[], unsigned long token);
extern int aa_stack_profile(const char *profile);
extern int aa_stack_onexec(const char *profile);

/*
 * aa_find_mountpoint mnt is an output pointer to a heap-allocated string
 *
 * This is a replica of %cstring_output_allocate(char **mnt, free(*$1))
 * that uses the ISVOID helper to work correctly on SWIG 4.3 or later.
 */
%typemap(in,noblock=1,numinputs=0) (char **mnt) ($*1_ltype temp_mnt = 0) {
  $1 = &temp_mnt;
}
%typemap(freearg,match="in") (char **mnt) ""
%typemap(argout,noblock=1,fragment="SWIG_FromCharPtr") (char **mnt) {
  ISVOID_APPEND_OUTPUT(SWIG_FromCharPtr(*$1));
  free(*$1);
}
/* The other errno-based functions should not always be returning the int value:
 * - Python exceptions signal success/failure status instead via the %exception 
 *   handler above.
 * - Perl (the other binding) has $! for accessing errno but would check the int
 *   return status first.
 *
 * The generated C code for (out) resets the return value to None
 * before appending the returned data (argout generated by %cstring stuff)
 */
#ifdef SWIGPYTHON
%typemap(out,noblock=1) int {
#if defined(VOID_Object)
	$result = VOID_Object;
#endif
}
#endif

/*
 * We can't use "typedef int pid_t" because we still support systems
 * with 16-bit PIDs and SWIG can't find sys/types.h
 *
 * Capture the passed-in value as a long because pid_t is guaranteed
 * to be a signed integer and because the aalogparse struct uses
 * (unsigned) longs to store pid values. While intmax_t would be more
 * technically correct, if sizeof(pid_t) > sizeof(long) then aalogparse
 * itself would also need fixing.
 */
%typemap(in,noblock=1,fragment="SWIG_AsVal_long") pid_t (int conv_pid, long pid_large) {
%#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
  static_assert(sizeof(pid_t) <= sizeof(long),
    "pid_t type is too large to be stored in a long");
%#endif
  conv_pid = SWIG_AsVal_long($input, &pid_large);
  if (!SWIG_IsOK(conv_pid)) {
    %argument_fail(conv_pid, "pid_t", $symname, $argnum);
  }
  /*
   * Cast the long to a pid_t and then cast back to check for overflow
   * Technically this is implementation-defined behaviour but we should be fine
   */
  $1 = (pid_t) pid_large;
  if ((long) $1 != pid_large) {
    SWIG_exception_fail(SWIG_OverflowError, "pid_t is too large");
  }
}

extern int aa_find_mountpoint(char **mnt);
extern int aa_getprocattr(pid_t tid, const char *attr, char **label, char **mode);
extern int aa_gettaskcon(pid_t target, char **label, char **mode);
extern int aa_getcon(char **label, char **mode);
extern int aa_getpeercon(int fd, char **label, char **mode);

/*
 * Typemaps for the boolean outputs of the query functions
 * Use boolean types for Python and int types elsewhere
 */
#ifdef SWIGPYTHON
// TODO: find a way to deduplicate these
%typemap(in, numinputs=0) int *allowed (int temp) {
  $1 = &temp;
}
%typemap(argout) int *allowed {
  ISVOID_APPEND_OUTPUT(PyBool_FromLong(*$1));
}

%typemap(in, numinputs=0) int *audited (int temp) {
  $1 = &temp;
}
%typemap(argout) int *audited {
  ISVOID_APPEND_OUTPUT(PyBool_FromLong(*$1));
}
#else
%apply int *OUTPUT { int *allowed };
%apply int *OUTPUT { int *audited };
#endif

/* Sync this with the apparmor.h */
/* Permission flags for the AA_CLASS_FILE mediation class */
#define AA_MAY_EXEC			(1 << 0)
#define AA_MAY_WRITE			(1 << 1)
#define AA_MAY_READ			(1 << 2)
#define AA_MAY_APPEND			(1 << 3)
#define AA_MAY_CREATE			(1 << 4)
#define AA_MAY_DELETE			(1 << 5)
#define AA_MAY_OPEN			(1 << 6)
#define AA_MAY_RENAME			(1 << 7)
#define AA_MAY_SETATTR			(1 << 8)
#define AA_MAY_GETATTR			(1 << 9)
#define AA_MAY_SETCRED			(1 << 10)
#define AA_MAY_GETCRED			(1 << 11)
#define AA_MAY_CHMOD			(1 << 12)
#define AA_MAY_CHOWN			(1 << 13)
#define AA_MAY_LOCK			0x8000
#define AA_EXEC_MMAP			0x10000
#define AA_MAY_LINK			0x40000
#define AA_MAY_ONEXEC			0x20000000
#define AA_MAY_CHANGE_PROFILE		0x40000000

extern int aa_query_file_path(uint32_t mask, const char *label,
			      const char *path, int *allowed, int *audited);
extern int aa_query_link_path(const char *label, const char *target,
			      const char *link, int *allowed, int *audited);

%exception;
