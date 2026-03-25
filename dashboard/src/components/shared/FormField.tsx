import React from 'react';

interface FormFieldProps {
  label: string;
  type: 'text' | 'textarea' | 'number' | 'select';
  value: string | number;
  onChange: (value: string) => void;
  placeholder?: string;
  options?: { label: string; value: string }[];
  required?: boolean;
  min?: number;
  max?: number;
  rows?: number;
  error?: string;
}

const baseInputClasses =
  'w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm';

export const FormField: React.FC<FormFieldProps> = ({
  label,
  type,
  value,
  onChange,
  placeholder,
  options,
  required,
  min,
  max,
  rows = 3,
  error,
}) => {
  const id = `field-${label.toLowerCase().replace(/\s+/g, '-')}`;

  const renderInput = () => {
    switch (type) {
      case 'textarea':
        return (
          <textarea
            id={id}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            required={required}
            rows={rows}
            className={baseInputClasses}
          />
        );

      case 'select':
        return (
          <select
            id={id}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            required={required}
            className={baseInputClasses}
          >
            {placeholder && (
              <option value="" disabled>
                {placeholder}
              </option>
            )}
            {options?.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        );

      case 'number':
        return (
          <input
            id={id}
            type="number"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            required={required}
            min={min}
            max={max}
            className={baseInputClasses}
          />
        );

      default:
        return (
          <input
            id={id}
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            required={required}
            className={baseInputClasses}
          />
        );
    }
  };

  return (
    <div className="mb-4">
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}
        {required && <span className="text-red-500 ml-1">*</span>}
      </label>
      {renderInput()}
      {error && <p className="mt-1 text-xs text-red-500">{error}</p>}
    </div>
  );
};
