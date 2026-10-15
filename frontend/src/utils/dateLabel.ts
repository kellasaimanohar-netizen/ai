/** "Oct 02" -> "2nd". The first of a month keeps its month so a long range stays readable: "1st Oct". */
export const ordinalDay = (label: string): string => {
  const [mon, dayText] = String(label).split(' ');
  const day = Number(dayText);
  if (!Number.isFinite(day)) return label;
  const tail = day % 100 >= 11 && day % 100 <= 13 ? 'th' : ({ 1: 'st', 2: 'nd', 3: 'rd' } as Record<number, string>)[day % 10] || 'th';
  return `${day}${tail}${day === 1 ? ` ${mon}` : ''}`;
};
