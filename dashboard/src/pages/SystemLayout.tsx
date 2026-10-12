import { Suspense } from 'react';
import { Outlet } from 'react-router-dom';


export default function SystemLayout() {
    return (
        <div className="flex flex-col min-h-0 w-full min-w-0 space-y-6 md:space-y-8">
            <Suspense
                fallback={
                    <div className="flex items-center justify-center py-16 text-sm text-slate-500 dark:text-slate-400">
                        Loading…
                    </div>
                }
            >
                <Outlet />
            </Suspense>
        </div>
    );
}

