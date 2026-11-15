/**
 * PREVENT-X Shared Error Formatting Utility
 * Safely extracts human-readable message strings from any error type:
 * strings, structured error objects ({ code, message }), Axios errors,
 * Error instances, arrays of validation errors, null, or undefined.
 * Guarantees that React JSX never crashes from attempting to render raw objects.
 */

export interface StructuredError {
  code?: string;
  message?: string;
  detail?: string | { code?: string; message?: string } | any[];
  [key: string]: any;
}

export type ErrorValue = string | StructuredError | Error | null | undefined;

export const formatErrorMessage = (err: unknown, fallback: string = 'An unexpected error occurred.'): string => {
  if (err == null) {
    return '';
  }
  if (typeof err === 'string') {
    return err;
  }
  if (typeof err === 'object') {
    const obj = err as Record<string, any>;

    // 0. Axios error response data
    if (obj.response && obj.response.data) {
      return formatErrorMessage(obj.response.data, fallback);
    }

    // 1. Direct message property (if string)
    if (obj.message != null && typeof obj.message === 'string') {
      const msg = obj.message.trim();
      if (msg) return msg;
    }

    // 2. Direct detail property (string)
    if (obj.detail != null && typeof obj.detail === 'string') {
      const det = obj.detail.trim();
      if (det) return det;
    }

    // 3. Nested detail object { code, message }
    if (typeof obj.detail === 'object' && obj.detail !== null) {
      if (obj.detail.message != null && typeof obj.detail.message === 'string') {
        const msg = obj.detail.message.trim();
        if (msg) return msg;
      }
      if (obj.detail.code != null && typeof obj.detail.code === 'string') {
        const cd = obj.detail.code.trim();
        if (cd) return cd;
      }
      if (Array.isArray(obj.detail)) {
        return formatErrorMessage(obj.detail, fallback);
      }
    }

    // 4. Direct code property
    if (obj.code != null && typeof obj.code === 'string') {
      const cd = obj.code.trim();
      if (cd) return cd;
    }

    // 5. Array of validation errors (e.g. FastAPI / Pydantic)
    if (Array.isArray(obj)) {
      const messages = obj
        .map((item) => {
          if (item == null) return '';
          if (typeof item === 'string') return item;
          if (typeof item === 'object') {
            return item.msg || item.message || '';
          }
          return String(item);
        })
        .filter(Boolean);
      if (messages.length > 0) {
        return messages.join(', ');
      }
    }
  }

  return fallback;
};
