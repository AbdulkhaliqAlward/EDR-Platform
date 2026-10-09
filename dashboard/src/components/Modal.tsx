import { useEffect, useId, useRef, type ReactNode } from 'react';
import ReactDOM from 'react-dom';
import { X } from 'lucide-react';

interface ModalProps {
    isOpen: boolean;
    onClose: () => void;
    title?: string;
    children: ReactNode;
    size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
    showCloseButton?: boolean;
    closeOnOverlayClick?: boolean;
    closeDisabled?: boolean;
    footer?: ReactNode;
}

const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-[90vw]',
};

let openModalCount = 0;
let previousBodyOverflow = '';

export function Modal({
    isOpen,
    onClose,
    title,
    children,
    size = 'md',
    showCloseButton = true,
    closeOnOverlayClick = true,
    closeDisabled = false,
    footer,
}: ModalProps) {
    const dialogRef = useRef<HTMLDivElement>(null);
    const titleId = useId();

    // Handle escape key (only the topmost of nested modals closes)
    useEffect(() => {
        const handleEscape = (e: KeyboardEvent) => {
            if (!isOpen) return;
            const dialogs = document.querySelectorAll('[role="dialog"][aria-modal="true"]');
            if (dialogs.length > 0 && dialogs[dialogs.length - 1] !== dialogRef.current) return;
            if (e.key === 'Escape') {
                e.preventDefault();
                e.stopImmediatePropagation();
                if (!closeDisabled) onClose();
                return;
            }
            if (e.key !== 'Tab' || !dialogRef.current) return;
            const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>('a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])'))
                .filter(element => !element.matches(':disabled') && element.getClientRects().length > 0);
            const first = focusable[0], last = focusable[focusable.length - 1];
            if (!first) { e.preventDefault(); dialogRef.current.focus(); }
            else if (e.shiftKey && (document.activeElement === first || !dialogRef.current.contains(document.activeElement))) { e.preventDefault(); last.focus(); }
            else if (!e.shiftKey && (document.activeElement === last || !dialogRef.current.contains(document.activeElement))) { e.preventDefault(); first.focus(); }
        };

        document.addEventListener('keydown', handleEscape);
        return () => document.removeEventListener('keydown', handleEscape);
    }, [isOpen, onClose, closeDisabled]);

    // Prevent body scroll when modal is open
    useEffect(() => {
        if (!isOpen) return;
        if (openModalCount++ === 0) {
            previousBodyOverflow = document.body.style.overflow;
            document.body.style.overflow = 'hidden';
        }
        return () => {
            if (--openModalCount === 0) document.body.style.overflow = previousBodyOverflow;
        };
    }, [isOpen]);

    if (!isOpen) return null;

    return ReactDOM.createPortal(
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
            {/* Overlay */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-md animate-fade-in"
                onClick={closeOnOverlayClick && !closeDisabled ? onClose : undefined}
                aria-hidden="true"
            />

            {/* Modal Content */}
            <div
                ref={dialogRef}
                className={`relative w-full ${sizeClasses[size]} bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700/80 rounded-2xl shadow-2xl dark:shadow-slate-900/60 animate-slide-up-fade overflow-hidden flex flex-col max-h-[90vh]`}
                role="dialog"
                tabIndex={-1}
                aria-modal="true"
                aria-labelledby={title ? titleId : undefined}
            >
                {/* Header */}
                {(title || showCloseButton) && (
                    <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700/80 bg-slate-50/80 dark:bg-slate-800/80 shrink-0">
                        {title && (
                            <h2 id={titleId} className="text-base font-bold text-slate-900 dark:text-white tracking-tight">
                                {title}
                            </h2>
                        )}
                        {showCloseButton && (
                            <button
                                type="button"
                                disabled={closeDisabled}
                                onClick={onClose}
                                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-all duration-150"
                                aria-label="Close modal"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                )}

                {/* Body */}
                <div className="min-w-0 px-6 py-5 overflow-y-auto flex-1">
                    {children}
                </div>

                {/* Footer */}
                {footer && (
                    <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700/80 bg-slate-50/80 dark:bg-slate-900/50 rounded-b-2xl shrink-0">
                        {footer}
                    </div>
                )}
            </div>
        </div>,
        document.body
    );
}

// Confirm Dialog Component
interface ConfirmDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    title: string;
    message: string;
    confirmText?: string;
    cancelText?: string;
    variant?: 'danger' | 'warning' | 'primary';
    isLoading?: boolean;
    errorMessage?: string | null;
}

export function ConfirmDialog({
    isOpen,
    onClose,
    onConfirm,
    title,
    message,
    confirmText = 'Confirm',
    cancelText = 'Cancel',
    variant = 'primary',
    isLoading = false,
    errorMessage,
}: ConfirmDialogProps) {
    const buttonVariants = {
        danger: 'bg-red-600 hover:bg-red-700 text-white',
        warning: 'bg-amber-600 hover:bg-amber-700 text-white',
        primary: 'bg-primary-600 hover:bg-primary-700 text-white',
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={title} size="sm" closeDisabled={isLoading}>
            <p className="text-gray-600 dark:text-gray-300">{message}</p>
            {errorMessage && <p role="alert" className="mt-3 text-sm text-rose-600 dark:text-rose-400">{errorMessage}</p>}
            <div className="flex justify-end gap-3 mt-6">
                <button
                    onClick={onClose}
                    disabled={isLoading}
                    className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50"
                >
                    {cancelText}
                </button>
                <button
                    onClick={onConfirm}
                    disabled={isLoading}
                    className={`px-4 py-2 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2 ${buttonVariants[variant]}`}
                >
                    {isLoading && (
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    )}
                    {confirmText}
                </button>
            </div>
        </Modal>
    );
}

export default Modal;
