from collections import Counter
from typing import List, Dict, Any
import json
import logging
from datetime import datetime


def generate_statistics(verdicts: List[Dict[str, Any]], all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics from verdict and results data"""
    # Initialize counters
    targeted_companies = Counter()
    hosting_providers = Counter()
    unknown_targets = 0

    # Process each verdict
    for verdict in verdicts:
        try:
            metadata = verdict.get('metadata', {})

            # Count hosting providers (ASN organizations)
            asn_org = metadata.get('asn_org')
            if asn_org:
                hosting_providers[asn_org] += 1

            # Count targeted brands/companies
            brands = metadata.get('targeted_brands', [])
            if not brands:
                unknown_targets += 1
                targeted_companies['Unknown'] += 1
            else:
                for brand in brands:
                    brand_name = brand.get('name')
                    if brand_name:
                        targeted_companies[brand_name] += 1

        except Exception as e:
            logging.error(f"Error processing verdict for statistics: {str(e)}")
            continue

    # Prepare statistics
    stats = {
        'timestamp': datetime.now().isoformat(),
        'total_analyzed': len(all_results),
        'total_malicious': len(verdicts),
        'malicious_percentage': round((len(verdicts) / len(all_results) * 100), 2) if all_results else 0,
        'unknown_target_count': unknown_targets,
        'unknown_target_percentage': round((unknown_targets / len(verdicts) * 100), 2) if verdicts else 0,
        'top_targeted_companies': [
            {'name': name, 'count': count}
            for name, count in targeted_companies.most_common(10)
        ],
        'top_hosting_providers': [
            {'name': name, 'count': count}
            for name, count in hosting_providers.most_common(10)
        ]
    }

    return stats


def save_statistics(stats: Dict[str, Any], stats_file: str):
    """Save statistics to a formatted text file"""
    try:
        with open(stats_file, 'w', encoding='utf-8') as f:
            f.write(f"URLScan Statistics Report - Generated at {stats['timestamp']}\n")
            f.write("=" * 80 + "\n\n")

            # Overall statistics
            f.write("Overall Statistics:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total URLs analyzed: {stats['total_analyzed']:,}\n")
            f.write(f"Total malicious verdicts: {stats['total_malicious']:,}\n")
            f.write(f"Malicious percentage: {stats['malicious_percentage']}%\n")
            f.write(f"Unknown targets: {stats['unknown_target_count']:,} ")
            f.write(f"({stats['unknown_target_percentage']}% of malicious)\n")
            f.write("\n")

            # Top targeted companies
            f.write("Top Targeted Companies/Organizations:\n")
            f.write("-" * 40 + "\n")
            for idx, company in enumerate(stats['top_targeted_companies'], 1):
                if company['name'] == 'Unknown':
                    continue  # Skip Unknown from top companies list since it's shown in overall stats
                f.write(f"{idx}. {company['name']}: {company['count']} times\n")
            f.write("\n")

            # Top hosting providers
            f.write("Top Hosting Providers:\n")
            f.write("-" * 40 + "\n")
            for idx, provider in enumerate(stats['top_hosting_providers'], 1):
                f.write(f"{idx}. {provider['name']}: {provider['count']} times\n")

    except Exception as e:
        logging.error(f"Error saving statistics: {str(e)}")


def update_statistics(verdicts_file: str, results_file: str, stats_file: str):
    """Update statistics when new verdicts are added"""
    try:
        # Load verdicts
        with open(verdicts_file, 'r', encoding='utf-8') as f:
            verdicts = json.load(f)

        # Load all results
        with open(results_file, 'r', encoding='utf-8') as f:
            all_results = json.load(f)

        # Generate and save statistics
        stats = generate_statistics(verdicts, all_results)
        save_statistics(stats, stats_file)

    except Exception as e:
        logging.error(f"Error updating statistics: {str(e)}")