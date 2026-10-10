import { memo } from 'react';
import logoUrl from '../assets/mitras-logo.png';

/** Display the supplied artwork without resampling or altering the original file. */
const MitrasLogo = memo(function MitrasLogo({ className = '', wordmark = false }: {
    className?: string;
    wordmark?: boolean;
}) {
    return (
        <svg className={`dark:brightness-0 dark:invert print:!filter-none ${className}`} viewBox={wordmark ? '150 20 690 610' : '250 20 490 460'}
            role="img" aria-label="MITRAS" xmlns="http://www.w3.org/2000/svg">
            <image href={logoUrl} width="1024" height="776" />
        </svg>
    );
});

export default MitrasLogo;
