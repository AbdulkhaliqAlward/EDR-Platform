import { Settings2 } from 'lucide-react';
import PageHeader from '../PageHeader';

export default function SettingsLayout({
    children,
}: {
    activeTab?: string;
    onChangeTab?: (id: string) => void;
    children: React.ReactNode;
    userRole?: string;
}) {
    return (
        <div className="flex-1 flex flex-col min-h-0 bg-slate-50 dark:bg-slate-950">
            <div className="px-6 md:px-10 pt-6 md:pt-8 shrink-0">
                <PageHeader
                    icon={Settings2}
                    eyebrow="Settings"
                    title="Platform preferences"
                />
            </div>

            <main className="flex-1 min-h-0 bg-slate-50 dark:bg-slate-950/80 p-6 md:p-10 overflow-auto">
                <div className="w-full max-w-none space-y-8 animate-fade-in">


                    {children}
                </div>
            </main>
        </div>
    );
}
