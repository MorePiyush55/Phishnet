import * as React from "react"
import { cn } from "../../lib/utils"

const Calendar = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    mode?: 'single' | 'multiple' | 'range';
    selected?: Date | Date[] | null;
    onSelect?: (date: Date | null) => void;
    initialFocus?: boolean;
  }
>(({ className, mode = 'single', selected, onSelect, initialFocus, ...props }, ref) => {
  const [currentDate, setCurrentDate] = React.useState(new Date());
  const [selectedDate, setSelectedDate] = React.useState<Date | null>(
    selected instanceof Date ? selected : null
  );

  const daysOfWeek = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];

  const getDaysInMonth = (date: Date) => {
    const year = date.getFullYear();
    const month = date.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const daysInMonth = lastDay.getDate();
    const startDay = firstDay.getDay();

    const days = [];
    
    // Add empty cells for days before the first day of the month
    for (let i = 0; i < startDay; i++) {
      days.push(null);
    }
    
    // Add days of the month
    for (let i = 1; i <= daysInMonth; i++) {
      days.push(new Date(year, month, i));
    }
    
    return days;
  };

  const handleDateClick = (date: Date | null) => {
    if (date) {
      setSelectedDate(date);
      onSelect?.(date);
    }
  };

  const navigateMonth = (direction: 1 | -1) => {
    setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + direction, 1));
  };

  const days = getDaysInMonth(currentDate);

  return (
    <div
      ref={ref}
      className={cn("p-3", className)}
      {...props}
    >
      <div className="flex items-center justify-between mb-4">
        <button
          onClick={() => navigateMonth(-1)}
          className="h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100"
        >
          ‹
        </button>
        <div className="text-sm font-medium">
          {monthNames[currentDate.getMonth()]} {currentDate.getFullYear()}
        </div>
        <button
          onClick={() => navigateMonth(1)}
          className="h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100"
        >
          ›
        </button>
      </div>
      <div className="grid grid-cols-7 gap-1 text-center text-sm">
        {daysOfWeek.map(day => (
          <div key={day} className="h-9 w-9 text-xs text-muted-foreground">
            {day}
          </div>
        ))}
        {days.map((date, index) => (
          <button
            key={index}
            onClick={() => handleDateClick(date)}
            className={cn(
              "h-9 w-9 p-0 font-normal aria-selected:opacity-100",
              date === null && "text-muted-foreground opacity-50",
              selectedDate && date && selectedDate.toDateString() === date.toDateString() && "bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground focus:bg-primary focus:text-primary-foreground",
              "hover:bg-accent hover:text-accent-foreground"
            )}
            disabled={date === null}
          >
            {date?.getDate()}
          </button>
        ))}
      </div>
    </div>
  )
})
Calendar.displayName = "Calendar"

export { Calendar }